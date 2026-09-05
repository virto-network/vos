//! Clean-generation signed `.vos` package envelopes.
//!
//! An envelope contains exactly one typed manifest and the complete ordered
//! closure of bytes named by that manifest. This module authenticates the
//! byte-level package and its compatibility contract without choosing an
//! Ed25519 implementation. Parsing standard-PVM bytes is intentionally a host
//! tooling boundary: callers must separately validate that `program`,
//! `outer_program`, and every Task dependency are the required canonical
//! standard-PVM image kind before admission.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::contract::{
    ActorAbiRange, ActorPackageContract, RuntimeMigrationPolicy, RuntimePackageContract,
    RuntimeResourceLimits,
};
use crate::{
    BlobRef, Hash, LaneSet, MAX_ACTOR_NAME_BYTES, MAX_CATALOG_ARTIFACT_BYTES,
    MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES, PackageKind,
    ProducerId, RUNTIME_ABI_ID, RuntimeCapabilities, RuntimeRequirements, STANDARD_MAX_ACTORS,
};

/// The only accepted clean-generation `.vos` envelope magic.
pub const PACKAGE_MAGIC: [u8; 4] = *b"VOS2";
/// The only accepted clean-generation `.vos` envelope version.
pub const PACKAGE_VERSION: u16 = 1;
pub const PACKAGE_PUBLIC_KEY_BYTES: usize = 32;
pub const PACKAGE_SIGNATURE_BYTES: usize = 64;
pub const MAX_PACKAGE_NAME_BYTES: usize = MAX_ACTOR_NAME_BYTES;
pub const MAX_PACKAGE_ARTIFACTS: usize = MAX_CATALOG_ARTIFACT_REFERENCES as usize;
pub const MAX_TASK_DEPENDENCIES: usize = MAX_PACKAGE_ARTIFACTS - 3;

const PACKAGE_SIGNING_MAGIC: [u8; 4] = *b"VSG2";
const BLOB_REF_WIRE_BYTES: usize = 32 + 8;
const PACKAGE_FIXED_WIRE_BYTES: usize = 4 + 2 + 32 + 1 + 4 + MAX_PACKAGE_NAME_BYTES + 512;

/// Absolute encoded-envelope ceiling. It accounts for artifact bytes, one
/// manifest reference and one closure reference per artifact, and fixed fields.
pub const MAX_PACKAGE_ENCODED_BYTES: usize = MAX_CATALOG_ARTIFACT_REFERENCED_BYTES as usize
    + MAX_PACKAGE_ARTIFACTS * (2 * BLOB_REF_WIRE_BYTES + 4)
    + PACKAGE_FIXED_WIRE_BYTES;

/// Producer authentication carried by either typed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageSigning {
    pub producer: ProducerId,
    pub public_key: [u8; PACKAGE_PUBLIC_KEY_BYTES],
    pub signature: [u8; PACKAGE_SIGNATURE_BYTES],
}

impl PackageSigning {
    fn validate_signer(&self) -> Result<(), PackageError> {
        if self.public_key == [0; PACKAGE_PUBLIC_KEY_BYTES] {
            return Err(PackageError::InvalidSignature);
        }
        if ProducerId::of_public_key(&self.public_key) != self.producer {
            return Err(PackageError::WrongProducer);
        }
        Ok(())
    }

    fn validate_signed(&self) -> Result<(), PackageError> {
        self.validate_signer()?;
        if self.signature == [0; PACKAGE_SIGNATURE_BYTES] {
            return Err(PackageError::InvalidSignature);
        }
        Ok(())
    }
}

/// Actor-only manifest. There is deliberately no runtime package or runtime
/// program field: runtime selection is an installation-time compatibility
/// decision and cannot be pinned by an actor package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPackageManifest {
    pub name: String,
    /// Content-addressed canonical standard actor PVM bytes.
    pub program: BlobRef,
    pub contract: ActorPackageContract,
    pub state_lane_schema: BlobRef,
    pub role_policy: BlobRef,
    /// Content-addressed Task dependencies, in strict BlobRef order.
    pub task_dependencies: Vec<BlobRef>,
    pub requirements: RuntimeRequirements,
    pub signing: PackageSigning,
}

/// AgentRuntime-only manifest. Actor schema, role policy, Task dependencies,
/// and a selected runtime pin are absent by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimePackageManifest {
    pub name: String,
    /// Content-addressed canonical outer standard PVM bytes.
    pub outer_program: BlobRef,
    pub contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
    pub signing: PackageSigning,
}

/// Exactly the two clean-generation package kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageManifest {
    Actor(ActorPackageManifest),
    AgentRuntime(AgentRuntimePackageManifest),
}

impl PackageManifest {
    pub fn kind(&self) -> PackageKind {
        match self {
            Self::Actor(manifest) => PackageKind::Actor {
                contract: manifest.contract,
                requirements: manifest.requirements,
            },
            Self::AgentRuntime(manifest) => PackageKind::AgentRuntime {
                contract: manifest.contract,
                capabilities: manifest.capabilities,
            },
        }
    }

    pub fn signing(&self) -> &PackageSigning {
        match self {
            Self::Actor(manifest) => &manifest.signing,
            Self::AgentRuntime(manifest) => &manifest.signing,
        }
    }

    pub fn signing_mut(&mut self) -> &mut PackageSigning {
        match self {
            Self::Actor(manifest) => &mut manifest.signing,
            Self::AgentRuntime(manifest) => &mut manifest.signing,
        }
    }

    fn validate(&self, require_signature: bool) -> Result<Vec<BlobRef>, PackageError> {
        let signing = self.signing();
        if require_signature {
            signing.validate_signed()?;
        } else {
            signing.validate_signer()?;
        }

        let mut references = Vec::new();
        match self {
            Self::Actor(manifest) => {
                validate_name(&manifest.name)?;
                if !manifest.contract.is_valid()
                    || manifest.task_dependencies.len() > MAX_TASK_DEPENDENCIES
                    || !strictly_sorted(&manifest.task_dependencies)
                {
                    return Err(PackageError::InvalidManifest);
                }
                references
                    .try_reserve_exact(3 + manifest.task_dependencies.len())
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.program.clone());
                references.push(manifest.state_lane_schema.clone());
                references.push(manifest.role_policy.clone());
                references.extend(manifest.task_dependencies.iter().cloned());
            }
            Self::AgentRuntime(manifest) => {
                validate_name(&manifest.name)?;
                if !manifest.contract.is_valid() || !valid_capabilities(manifest.capabilities) {
                    return Err(PackageError::InvalidManifest);
                }
                references
                    .try_reserve_exact(1)
                    .map_err(|_| PackageError::LimitExceeded)?;
                references.push(manifest.outer_program.clone());
            }
        }
        validate_reference_set(&mut references)?;
        Ok(references)
    }
}

/// One member of the exact, identity-ordered package closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageArtifact {
    pub identity: BlobRef,
    pub bytes: Vec<u8>,
}

/// Complete signed `.vos` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageEnvelope {
    pub manifest: PackageManifest,
    /// Strictly ordered closure; every manifest reference occurs exactly once.
    pub artifacts: Vec<PackageArtifact>,
}

impl PackageEnvelope {
    /// Validate canonical shape, signer binding, signature presence, and exact
    /// content-addressed closure. This does not perform signature verification.
    pub fn validate_shape(&self) -> Result<(), PackageError> {
        let expected = self.manifest.validate(true)?;
        validate_owned_closure(&expected, &self.artifacts)
    }

    /// Canonical bytes covered by the Ed25519 signature. The signature field
    /// itself is omitted; all other manifest fields and ordered closure
    /// identities are included.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PackageError> {
        let expected = self.manifest.validate(false)?;
        validate_owned_closure(&expected, &self.artifacts)?;
        let capacity = signing_encoded_len(&self.manifest, expected.len())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PackageError::LimitExceeded)?;
        bytes.extend_from_slice(&PACKAGE_SIGNING_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &self.manifest, false);
        encoder.list(&self.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
        });
        if bytes.len() != capacity || bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Verify shape and signature with a caller-supplied Ed25519 provider.
    pub fn verify<V: PackageVerifier>(&self, verifier: &V) -> Result<(), PackageError> {
        self.validate_shape()?;
        let signing = self.manifest.signing();
        let message = self.signing_bytes()?;
        if !verifier.verify(&signing.public_key, &message, &signing.signature) {
            return Err(PackageError::InvalidSignature);
        }
        Ok(())
    }

    /// Whether this package can be selected with a particular runtime.
    pub fn is_compatible_with(
        &self,
        runtime_contract: RuntimePackageContract,
        runtime_capabilities: RuntimeCapabilities,
    ) -> bool {
        self.validate_shape().is_ok()
            && valid_capabilities(runtime_capabilities)
            && self
                .manifest
                .kind()
                .is_compatible_with(runtime_contract, runtime_capabilities)
    }

    pub fn require_compatible_with(
        &self,
        runtime_contract: RuntimePackageContract,
        runtime_capabilities: RuntimeCapabilities,
    ) -> Result<(), PackageError> {
        self.validate_shape()?;
        (valid_capabilities(runtime_capabilities)
            && self
                .manifest
                .kind()
                .is_compatible_with(runtime_contract, runtime_capabilities))
        .then_some(())
        .ok_or(PackageError::IncompatibleRuntime)
    }

    /// Encode the one accepted clean-generation envelope representation.
    pub fn encode(&self) -> Result<Vec<u8>, PackageError> {
        self.validate_shape()?;
        let capacity = envelope_encoded_len(&self.manifest, &self.artifacts)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| PackageError::LimitExceeded)?;
        bytes.extend_from_slice(&PACKAGE_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &self.manifest, true);
        encoder.list(&self.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
            encoder.bytes(&artifact.bytes);
        });
        if bytes.len() != capacity || bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        Ok(bytes)
    }

    /// Decode with all counts and byte totals checked before artifact contents
    /// are allocated. Unknown tags, old magic, trailing bytes, and noncanonical
    /// ordering are rejected rather than normalized.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackageError> {
        if bytes.len() > MAX_PACKAGE_ENCODED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(PACKAGE_MAGIC.len())? != PACKAGE_MAGIC {
            return Err(DecodeError::InvalidTag.into());
        }
        if decoder.u16()? != PACKAGE_VERSION {
            return Err(DecodeError::InvalidTag.into());
        }
        if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform.into());
        }

        let manifest = decode_manifest(&mut decoder)?;
        let expected = manifest.validate(true)?;
        let count = decoder.u32()? as usize;
        if count > MAX_PACKAGE_ARTIFACTS {
            return Err(PackageError::LimitExceeded);
        }
        if count != expected.len() {
            return Err(PackageError::InvalidClosure);
        }

        let mut borrowed = Vec::new();
        borrowed
            .try_reserve_exact(count)
            .map_err(|_| PackageError::LimitExceeded)?;
        let mut total = 0u64;
        for expected_identity in &expected {
            let identity = decode_blob(&mut decoder)?;
            if identity != *expected_identity {
                return Err(PackageError::InvalidClosure);
            }
            let artifact_bytes = decoder.bytes_ref_bounded(MAX_CATALOG_ARTIFACT_BYTES as usize)?;
            total = total
                .checked_add(artifact_bytes.len() as u64)
                .ok_or(PackageError::LimitExceeded)?;
            if total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES {
                return Err(PackageError::LimitExceeded);
            }
            if !identity.matches(artifact_bytes) {
                return Err(PackageError::ArtifactMismatch);
            }
            borrowed.push((identity, artifact_bytes));
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes.into());
        }

        // All attacker-controlled sizes, identities, and hashes have now been
        // preflighted. Only then copy artifact contents into the owned model.
        let mut artifacts = Vec::new();
        artifacts
            .try_reserve_exact(borrowed.len())
            .map_err(|_| PackageError::LimitExceeded)?;
        for (identity, source) in borrowed {
            let mut artifact_bytes = Vec::new();
            artifact_bytes
                .try_reserve_exact(source.len())
                .map_err(|_| PackageError::LimitExceeded)?;
            artifact_bytes.extend_from_slice(source);
            artifacts.push(PackageArtifact {
                identity,
                bytes: artifact_bytes,
            });
        }
        let envelope = Self {
            manifest,
            artifacts,
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    /// Content identity of the exact encoded envelope bytes.
    pub fn package_ref(&self) -> Result<BlobRef, PackageError> {
        Ok(BlobRef::of_bytes(&self.encode()?))
    }
}

/// Signature verifier supplied by a no_std guest or host. Implementations are
/// expected to perform exact Ed25519 verification for the provided key.
pub trait PackageVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Decode(DecodeError),
    InvalidManifest,
    WrongProducer,
    InvalidSignature,
    InvalidClosure,
    ArtifactMismatch,
    LimitExceeded,
    IncompatibleRuntime,
}

impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidManifest => formatter.write_str("invalid package manifest"),
            Self::WrongProducer => formatter.write_str("producer does not match public key"),
            Self::InvalidSignature => formatter.write_str("invalid package signature"),
            Self::InvalidClosure => {
                formatter.write_str("package closure is not exact and canonical")
            }
            Self::ArtifactMismatch => {
                formatter.write_str("package artifact does not match its content identity")
            }
            Self::LimitExceeded => formatter.write_str("package limit exceeded"),
            Self::IncompatibleRuntime => {
                formatter.write_str("package is incompatible with runtime")
            }
        }
    }
}

impl core::error::Error for PackageError {}

impl From<DecodeError> for PackageError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

fn validate_name(name: &str) -> Result<(), PackageError> {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_BYTES {
        return Err(PackageError::InvalidManifest);
    }
    Ok(())
}

fn valid_capabilities(capabilities: RuntimeCapabilities) -> bool {
    capabilities.max_actors != 0 && capabilities.max_actors <= STANDARD_MAX_ACTORS
}

fn strictly_sorted(values: &[BlobRef]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_reference_set(references: &mut [BlobRef]) -> Result<(), PackageError> {
    if references.is_empty() || references.len() > MAX_PACKAGE_ARTIFACTS {
        return Err(PackageError::LimitExceeded);
    }
    if references
        .iter()
        .any(|reference| !crate::model::valid_blob(reference))
    {
        return Err(PackageError::InvalidManifest);
    }
    references.sort_unstable();
    if !strictly_sorted(references) {
        return Err(PackageError::InvalidClosure);
    }
    let mut total = 0u64;
    for reference in references {
        total = total
            .checked_add(reference.len)
            .ok_or(PackageError::LimitExceeded)?;
        if total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES {
            return Err(PackageError::LimitExceeded);
        }
    }
    Ok(())
}

fn validate_owned_closure(
    expected: &[BlobRef],
    artifacts: &[PackageArtifact],
) -> Result<(), PackageError> {
    if artifacts.len() != expected.len() {
        return Err(PackageError::InvalidClosure);
    }
    let mut total = 0u64;
    for (artifact, expected_identity) in artifacts.iter().zip(expected) {
        if artifact.identity != *expected_identity {
            return Err(PackageError::InvalidClosure);
        }
        total = total
            .checked_add(artifact.bytes.len() as u64)
            .ok_or(PackageError::LimitExceeded)?;
        if artifact.bytes.len() as u64 > MAX_CATALOG_ARTIFACT_BYTES
            || total > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        {
            return Err(PackageError::LimitExceeded);
        }
        if !artifact.identity.matches(&artifact.bytes) {
            return Err(PackageError::ArtifactMismatch);
        }
    }
    Ok(())
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

fn encode_requirements(encoder: &mut Encoder<'_>, value: RuntimeRequirements) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    encoder.bool(value.proofs);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, value: RuntimeCapabilities) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    encoder.bool(value.proofs);
    encoder.u32(value.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    let value = RuntimeCapabilities {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
        max_actors: decoder.u32()?,
    };
    valid_capabilities(value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
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

fn encode_signing(encoder: &mut Encoder<'_>, signing: &PackageSigning, include_signature: bool) {
    encoder.fixed(signing.producer.as_bytes());
    encoder.fixed(&signing.public_key);
    if include_signature {
        encoder.0.extend_from_slice(&signing.signature);
    }
}

fn decode_signing(decoder: &mut Decoder<'_>) -> Result<PackageSigning, DecodeError> {
    Ok(PackageSigning {
        producer: ProducerId(decoder.fixed()?),
        public_key: decoder.fixed()?,
        signature: decoder
            .take(PACKAGE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    })
}

fn encode_manifest(encoder: &mut Encoder<'_>, manifest: &PackageManifest, include_signature: bool) {
    match manifest {
        PackageManifest::Actor(manifest) => {
            encoder.u8(0);
            encoder.string(&manifest.name);
            encode_blob(encoder, &manifest.program);
            encode_actor_contract(encoder, manifest.contract);
            encode_blob(encoder, &manifest.state_lane_schema);
            encode_blob(encoder, &manifest.role_policy);
            encoder.list(&manifest.task_dependencies, encode_blob);
            encode_requirements(encoder, manifest.requirements);
            encode_signing(encoder, &manifest.signing, include_signature);
        }
        PackageManifest::AgentRuntime(manifest) => {
            encoder.u8(1);
            encoder.string(&manifest.name);
            encode_blob(encoder, &manifest.outer_program);
            encode_runtime_contract(encoder, manifest.contract);
            encode_capabilities(encoder, manifest.capabilities);
            encode_signing(encoder, &manifest.signing, include_signature);
        }
    }
}

fn decode_manifest(decoder: &mut Decoder<'_>) -> Result<PackageManifest, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PackageManifest::Actor(ActorPackageManifest {
            name: decoder.string_bounded(MAX_PACKAGE_NAME_BYTES)?,
            program: decode_blob(decoder)?,
            contract: decode_actor_contract(decoder)?,
            state_lane_schema: decode_blob(decoder)?,
            role_policy: decode_blob(decoder)?,
            task_dependencies: decoder.list_bounded(MAX_TASK_DEPENDENCIES, decode_blob)?,
            requirements: decode_requirements(decoder)?,
            signing: decode_signing(decoder)?,
        })),
        1 => Ok(PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: decoder.string_bounded(MAX_PACKAGE_NAME_BYTES)?,
            outer_program: decode_blob(decoder)?,
            contract: decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
            signing: decode_signing(decoder)?,
        })),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn manifest_encoded_len(
    manifest: &PackageManifest,
    include_signature: bool,
) -> Result<usize, PackageError> {
    let signature_bytes = if include_signature {
        PACKAGE_SIGNATURE_BYTES
    } else {
        0
    };
    let common = 1usize
        .checked_add(4)
        .and_then(|value| {
            value.checked_add(match manifest {
                PackageManifest::Actor(manifest) => manifest.name.len(),
                PackageManifest::AgentRuntime(manifest) => manifest.name.len(),
            })
        })
        .and_then(|value| value.checked_add(32 + 32 + signature_bytes))
        .ok_or(PackageError::LimitExceeded)?;
    match manifest {
        PackageManifest::Actor(manifest) => common
            .checked_add(BLOB_REF_WIRE_BYTES * 3 + 4 + 4 + 3)
            .and_then(|value| {
                value.checked_add(manifest.task_dependencies.len() * BLOB_REF_WIRE_BYTES)
            })
            .ok_or(PackageError::LimitExceeded),
        PackageManifest::AgentRuntime(_) => common
            .checked_add(BLOB_REF_WIRE_BYTES + 32 + 4 + 4 + 32 + 4 + 4 + 8 + 1 + 1 + 1 + 1 + 4)
            .ok_or(PackageError::LimitExceeded),
    }
}

fn signing_encoded_len(
    manifest: &PackageManifest,
    artifact_count: usize,
) -> Result<usize, PackageError> {
    (4usize + 2 + 32)
        .checked_add(manifest_encoded_len(manifest, false)?)
        .and_then(|value| value.checked_add(4 + artifact_count * BLOB_REF_WIRE_BYTES))
        .filter(|value| *value <= MAX_PACKAGE_ENCODED_BYTES)
        .ok_or(PackageError::LimitExceeded)
}

fn envelope_encoded_len(
    manifest: &PackageManifest,
    artifacts: &[PackageArtifact],
) -> Result<usize, PackageError> {
    let mut length = (4usize + 2 + 32)
        .checked_add(manifest_encoded_len(manifest, true)?)
        .and_then(|value| value.checked_add(4))
        .ok_or(PackageError::LimitExceeded)?;
    for artifact in artifacts {
        length = length
            .checked_add(BLOB_REF_WIRE_BYTES + 4)
            .and_then(|value| value.checked_add(artifact.bytes.len()))
            .ok_or(PackageError::LimitExceeded)?;
    }
    (length <= MAX_PACKAGE_ENCODED_BYTES)
        .then_some(length)
        .ok_or(PackageError::LimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier;

    impl PackageVerifier for TestVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn test_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(b"vos/test/package-signature/first", &[public_key, message]);
        let second = Hash::digest(b"vos/test/package-signature/second", &[public_key, message]);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    fn unsigned_signing() -> PackageSigning {
        let public_key = [0x5a; PACKAGE_PUBLIC_KEY_BYTES];
        PackageSigning {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; PACKAGE_SIGNATURE_BYTES],
        }
    }

    fn artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn sorted_artifacts(values: &[&[u8]]) -> Vec<PackageArtifact> {
        let mut artifacts: Vec<_> = values.iter().map(|bytes| artifact(bytes)).collect();
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        artifacts
    }

    fn sign(mut envelope: PackageEnvelope) -> PackageEnvelope {
        let message = envelope.signing_bytes().unwrap();
        let public_key = envelope.manifest.signing().public_key;
        envelope.manifest.signing_mut().signature = test_signature(&public_key, &message);
        envelope
    }

    fn actor_package() -> PackageEnvelope {
        let program = b"canonical actor pvm".as_slice();
        let schema = b"state lane schema".as_slice();
        let policy = b"role policy".as_slice();
        let task_a = b"task dependency a".as_slice();
        let task_b = b"task dependency b".as_slice();
        let mut dependencies = alloc::vec![BlobRef::of_bytes(task_a), BlobRef::of_bytes(task_b)];
        dependencies.sort_unstable();
        sign(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "counter".into(),
                program: BlobRef::of_bytes(program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(schema),
                role_policy: BlobRef::of_bytes(policy),
                task_dependencies: dependencies,
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(crate::StateLane::Merge),
                    scheduling: true,
                    proofs: true,
                },
                signing: unsigned_signing(),
            }),
            artifacts: sorted_artifacts(&[program, schema, policy, task_a, task_b]),
        })
    }

    fn runtime_package() -> PackageEnvelope {
        let outer_program = b"canonical outer runtime pvm".as_slice();
        sign(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "standard-agent-runtime".into(),
                outer_program: BlobRef::of_bytes(outer_program),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities {
                    lanes: LaneSet::ALL,
                    scheduling: true,
                    proofs: true,
                    max_actors: STANDARD_MAX_ACTORS,
                },
                signing: unsigned_signing(),
            }),
            artifacts: sorted_artifacts(&[outer_program]),
        })
    }

    fn encode_unchecked(envelope: &PackageEnvelope) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACKAGE_MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(PACKAGE_VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encode_manifest(&mut encoder, &envelope.manifest, true);
        encoder.list(&envelope.artifacts, |encoder, artifact| {
            encode_blob(encoder, &artifact.identity);
            encoder.bytes(&artifact.bytes);
        });
        bytes
    }

    fn actor_requirements_offset(manifest: &ActorPackageManifest) -> usize {
        4 + 2
            + 32
            + 1
            + 4
            + manifest.name.len()
            + BLOB_REF_WIRE_BYTES
            + 4
            + BLOB_REF_WIRE_BYTES * 2
            + 4
            + manifest.task_dependencies.len() * BLOB_REF_WIRE_BYTES
    }

    fn synthetic_reference(index: u32, len: u64) -> BlobRef {
        let mut hash = [0; 32];
        hash[..4].copy_from_slice(&index.to_be_bytes());
        hash[31] = 1;
        BlobRef {
            hash: Hash(hash),
            len,
        }
    }

    #[test]
    fn actor_round_trip_is_canonical_and_content_addressed() {
        let package = actor_package();
        package.verify(&TestVerifier).unwrap();
        let encoded = package.encode().unwrap();
        let decoded = PackageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, package);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(package.package_ref().unwrap(), BlobRef::of_bytes(&encoded));
        assert!(matches!(package.manifest.kind(), PackageKind::Actor { .. }));
    }

    #[test]
    fn actor_manifest_cannot_represent_a_runtime_pin() {
        let PackageManifest::Actor(manifest) = &actor_package().manifest else {
            panic!("fixture must be an actor");
        };
        // This exhaustive pattern is intentionally kept without `..`: adding
        // any hidden runtime selection to the actor manifest breaks this test
        // at compile time.
        let ActorPackageManifest {
            name: _,
            program: _,
            contract: _,
            state_lane_schema: _,
            role_policy: _,
            task_dependencies: _,
            requirements: _,
            signing: _,
        } = manifest;
    }

    #[test]
    fn runtime_round_trip_has_only_its_outer_program_closure() {
        let package = runtime_package();
        package.verify(&TestVerifier).unwrap();
        let encoded = package.encode().unwrap();
        let decoded = PackageEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, package);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert!(matches!(
            package.manifest.kind(),
            PackageKind::AgentRuntime { .. }
        ));

        let mut with_actor_artifact = package;
        with_actor_artifact
            .artifacts
            .push(artifact(b"actor-only schema"));
        with_actor_artifact
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        assert_eq!(
            with_actor_artifact.validate_shape(),
            Err(PackageError::InvalidClosure)
        );
    }

    #[test]
    fn signature_and_exact_producer_are_fail_closed() {
        let package = actor_package();

        let mut signature_tamper = package.clone();
        signature_tamper.manifest.signing_mut().signature[0] ^= 1;
        assert_eq!(
            signature_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );

        let mut manifest_tamper = package.clone();
        let PackageManifest::Actor(manifest) = &mut manifest_tamper.manifest else {
            unreachable!();
        };
        manifest.name.push('!');
        assert_eq!(
            manifest_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );

        let mut wrong_producer = package.clone();
        wrong_producer.manifest.signing_mut().producer = ProducerId::ZERO;
        assert_eq!(
            wrong_producer.validate_shape(),
            Err(PackageError::WrongProducer)
        );

        let mut wrong_key = package.clone();
        wrong_key.manifest.signing_mut().public_key[0] ^= 1;
        assert_eq!(wrong_key.validate_shape(), Err(PackageError::WrongProducer));

        let mut closure_identity_tamper = package;
        let replacement = artifact(b"different canonical actor pvm");
        let PackageManifest::Actor(manifest) = &mut closure_identity_tamper.manifest else {
            unreachable!();
        };
        let old_program = core::mem::replace(&mut manifest.program, replacement.identity.clone());
        let closure_entry = closure_identity_tamper
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.identity == old_program)
            .unwrap();
        *closure_entry = replacement;
        closure_identity_tamper
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        closure_identity_tamper.validate_shape().unwrap();
        assert_eq!(
            closure_identity_tamper.verify(&TestVerifier),
            Err(PackageError::InvalidSignature)
        );
    }

    #[test]
    fn unsigned_shape_can_be_signed_but_not_encoded() {
        let mut package = actor_package();
        package.manifest.signing_mut().signature = [0; PACKAGE_SIGNATURE_BYTES];
        assert!(!package.signing_bytes().unwrap().is_empty());
        assert_eq!(package.encode(), Err(PackageError::InvalidSignature));
    }

    #[test]
    fn closure_rejects_swaps_duplicates_missing_extra_and_mismatched_bytes() {
        let package = actor_package();

        let mut swapped = package.clone();
        swapped.artifacts.swap(0, 1);
        assert_eq!(swapped.validate_shape(), Err(PackageError::InvalidClosure));
        assert_eq!(
            PackageEnvelope::decode(&encode_unchecked(&swapped)),
            Err(PackageError::InvalidClosure)
        );

        let mut duplicate = package.clone();
        duplicate.artifacts[1] = duplicate.artifacts[0].clone();
        assert_eq!(
            duplicate.validate_shape(),
            Err(PackageError::InvalidClosure)
        );

        let mut missing = package.clone();
        missing.artifacts.pop();
        assert_eq!(missing.validate_shape(), Err(PackageError::InvalidClosure));

        let mut extra = package.clone();
        extra.artifacts.push(artifact(b"unreferenced artifact"));
        extra
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        assert_eq!(extra.validate_shape(), Err(PackageError::InvalidClosure));

        let mut mismatched = package;
        mismatched.artifacts[0].bytes[0] ^= 1;
        assert_eq!(
            mismatched.validate_shape(),
            Err(PackageError::ArtifactMismatch)
        );
    }

    #[test]
    fn dependency_order_and_cross_role_aliases_are_rejected() {
        let mut unsorted = actor_package();
        let PackageManifest::Actor(manifest) = &mut unsorted.manifest else {
            unreachable!();
        };
        manifest.task_dependencies.swap(0, 1);
        assert_eq!(
            unsorted.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut duplicate = actor_package();
        let PackageManifest::Actor(manifest) = &mut duplicate.manifest else {
            unreachable!();
        };
        manifest.task_dependencies[1] = manifest.task_dependencies[0].clone();
        assert_eq!(
            duplicate.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut alias = actor_package();
        let PackageManifest::Actor(manifest) = &mut alias.manifest else {
            unreachable!();
        };
        manifest.state_lane_schema = manifest.program.clone();
        assert_eq!(alias.validate_shape(), Err(PackageError::InvalidClosure));
    }

    #[test]
    fn manifest_reference_limits_are_checked_without_artifact_allocation() {
        let mut long_name = actor_package();
        let PackageManifest::Actor(manifest) = &mut long_name.manifest else {
            unreachable!();
        };
        manifest.name = "x".repeat(MAX_PACKAGE_NAME_BYTES + 1);
        assert_eq!(
            long_name.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut oversized = actor_package();
        let PackageManifest::Actor(manifest) = &mut oversized.manifest else {
            unreachable!();
        };
        manifest.program.len = MAX_CATALOG_ARTIFACT_BYTES + 1;
        assert_eq!(
            oversized.validate_shape(),
            Err(PackageError::InvalidManifest)
        );

        let mut aggregate = actor_package();
        let PackageManifest::Actor(manifest) = &mut aggregate.manifest else {
            unreachable!();
        };
        manifest.task_dependencies = (1..=9)
            .map(|index| synthetic_reference(index, MAX_CATALOG_ARTIFACT_BYTES))
            .collect();
        assert_eq!(aggregate.signing_bytes(), Err(PackageError::LimitExceeded));

        let mut cardinality = actor_package();
        let PackageManifest::Actor(manifest) = &mut cardinality.manifest else {
            unreachable!();
        };
        manifest.task_dependencies = (1..=(MAX_TASK_DEPENDENCIES as u32 + 1))
            .map(|index| synthetic_reference(index, 1))
            .collect();
        assert_eq!(
            cardinality.signing_bytes(),
            Err(PackageError::InvalidManifest)
        );
    }

    #[test]
    fn decoder_rejects_hostile_lengths_unknown_tags_and_noncanonical_values() {
        let package = actor_package();
        let encoded = package.encode().unwrap();

        let mut hostile_name = Vec::new();
        hostile_name.extend_from_slice(&PACKAGE_MAGIC);
        hostile_name.extend_from_slice(&PACKAGE_VERSION.to_le_bytes());
        hostile_name.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        hostile_name.push(0);
        hostile_name.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_name),
            Err(PackageError::Decode(DecodeError::LimitExceeded))
        );

        let closure_offset = 4 + 2 + 32 + manifest_encoded_len(&package.manifest, true).unwrap();
        let mut hostile_count = encoded.clone();
        hostile_count[closure_offset..closure_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_count),
            Err(PackageError::LimitExceeded)
        );

        let mut hostile_artifact = encoded.clone();
        let artifact_length_offset = closure_offset + 4 + BLOB_REF_WIRE_BYTES;
        hostile_artifact[artifact_length_offset..artifact_length_offset + 4]
            .copy_from_slice(&((MAX_CATALOG_ARTIFACT_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&hostile_artifact),
            Err(PackageError::Decode(DecodeError::LimitExceeded))
        );

        let mut unknown_kind = encoded.clone();
        unknown_kind[4 + 2 + 32] = 0xff;
        assert_eq!(
            PackageEnvelope::decode(&unknown_kind),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );

        let PackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!();
        };
        let requirements_offset = actor_requirements_offset(manifest);
        let mut invalid_lanes = encoded.clone();
        invalid_lanes[requirements_offset] = 0x80;
        assert_eq!(
            PackageEnvelope::decode(&invalid_lanes),
            Err(PackageError::Decode(DecodeError::NonCanonical))
        );
        let mut invalid_bool = encoded;
        invalid_bool[requirements_offset + 1] = 2;
        assert_eq!(
            PackageEnvelope::decode(&invalid_bool),
            Err(PackageError::Decode(DecodeError::NonCanonical))
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes_old_magic_and_unknown_version() {
        let encoded = runtime_package().encode().unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            PackageEnvelope::decode(&trailing),
            Err(PackageError::Decode(DecodeError::TrailingBytes))
        );

        let mut previous_generation = encoded.clone();
        previous_generation[..4].copy_from_slice(b"VOSK");
        assert_eq!(
            PackageEnvelope::decode(&previous_generation),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );

        let mut unknown_version = encoded;
        unknown_version[4..6].copy_from_slice(&(PACKAGE_VERSION + 1).to_le_bytes());
        assert_eq!(
            PackageEnvelope::decode(&unknown_version),
            Err(PackageError::Decode(DecodeError::InvalidTag))
        );
    }

    #[test]
    fn selected_runtime_must_cover_actor_contract_lanes_and_capabilities() {
        let package = actor_package();
        let contract = RuntimePackageContract::canonical();
        let insufficient = RuntimeCapabilities::standard();
        assert!(!package.is_compatible_with(contract, insufficient));
        assert_eq!(
            package.require_compatible_with(contract, insufficient),
            Err(PackageError::IncompatibleRuntime)
        );

        let sufficient = RuntimeCapabilities {
            lanes: LaneSet::ALL,
            scheduling: true,
            proofs: true,
            max_actors: STANDARD_MAX_ACTORS,
        };
        assert!(package.is_compatible_with(contract, sufficient));
        package
            .require_compatible_with(contract, sufficient)
            .unwrap();

        let mut incompatible_abi = package;
        let PackageManifest::Actor(manifest) = &mut incompatible_abi.manifest else {
            unreachable!();
        };
        manifest.contract.actor_abi += 1;
        assert!(!incompatible_abi.is_compatible_with(contract, sufficient));

        let invalid_capacity = RuntimeCapabilities {
            max_actors: 0,
            ..sufficient
        };
        assert!(!runtime_package().is_compatible_with(contract, invalid_capacity));
    }
}
