//! Signed packages for actors and agent runtimes.
//!
//! Actor packages state the actor ABI and capabilities they need; they never
//! pin the runtime that will host them. Agent-runtime packages bind the stable
//! lifecycle ABI, supported actor-ABI range, canonical control schema,
//! resource ceilings, migration policy, and capabilities they implement.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(test)]
use super::contract::{ActorAbiRange, ActorPackageContract};
use super::contract::{
    RuntimeMigrationPolicy, RuntimePackageContract, decode_actor_contract, decode_runtime_contract,
    encode_actor_contract, encode_runtime_contract,
};
use super::{LaneSet, PackageKind, RuntimeCapabilities, RuntimeRequirements};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{DeploymentId, Hash, ProducerId, ProgramId};
use crate::service::{
    DeploymentSignature, PackageDiagnostics, PackageRolePolicies, PackageTaskDependency,
    artifact_hash, task_dependencies_hash,
};

/// Maximum complete canonical agent-package wire. Packages cross transport
/// and durable catalog boundaries, so accepting the generic 64-MiB service
/// wire limit here would permit a single package to monopolize both.
pub const MAX_ENCODED_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum generated public interface artifact.
pub const MAX_PACKAGE_INTERFACES_BYTES: usize = 256 * 1024;
/// Maximum public actor metadata/schema artifact. The agent-specific state
/// schema has its own stricter [`super::schema::MAX_ENCODED_BYTES`] bound.
pub const MAX_PACKAGE_SCHEMAS_BYTES: usize = 256 * 1024;
/// Maximum aggregate executable bytes across signed Task dependencies.
pub const MAX_PACKAGE_TASK_BYTES: usize = 4 * 1024 * 1024;
/// Maximum aggregate optional ELF and source-map diagnostics.
pub const MAX_PACKAGE_DIAGNOSTICS_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKAGE_NAME_BYTES: usize = crate::service::MAX_ACTOR_NAME_BYTES;
const MAX_PACKAGE_SIGNING_KEY_BYTES: usize = 4 * 1024;
const MAX_PACKAGE_SIGNATURE_BYTES: usize = 4 * 1024;

fn is_valid_program(program: &[u8]) -> bool {
    // Production package admission runs in a std host, where the selected
    // executor's opcode and instruction-boundary checks are available. Guest
    // runtimes retain the portable structural check; they only observe
    // packages that a host has already admitted.
    #[cfg(feature = "std")]
    {
        vos_pvm::spi::parse_standard_program(program).is_some()
    }
    #[cfg(not(feature = "std"))]
    {
        vos_pvm_program::parse_standard_program(program).is_some()
    }
}

/// Derive the runtime features authenticated by an actor package.
///
/// State lanes live in the agent schema, while proof and scheduler use are
/// part of the public method contract. Keeping the derivation here gives the
/// builder and package verifier one fail-closed rule: callers cannot sign a
/// weaker requirement set than the actor metadata actually needs.
pub fn actor_runtime_requirements(
    schema: &super::schema::ParsedSchema,
    metadata: &crate::metadata::ParsedMeta,
    has_task_dependencies: bool,
) -> RuntimeRequirements {
    RuntimeRequirements {
        lanes: schema.lanes(),
        scheduling: metadata.messages.iter().any(|message| message.mode != 0),
        proofs: metadata.provable
            || has_task_dependencies
            || metadata.messages.iter().any(|message| message.attested),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageManifest {
    pub name: String,
    pub platform: Hash,
    pub execution_semantics: Hash,
    pub kind: PackageKind,
    pub program: ProgramId,
    pub interfaces_hash: Hash,
    pub role_policies_hash: Hash,
    pub schemas_hash: Hash,
    pub agent_schema_hash: Hash,
    pub dependencies_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub manifest: PackageManifest,
    pub pvm: Vec<u8>,
    pub generated_interfaces: Vec<u8>,
    pub role_policies: Vec<u8>,
    pub schemas: Vec<u8>,
    pub agent_schema: Vec<u8>,
    pub task_dependencies: Vec<PackageTaskDependency>,
    pub diagnostics: Option<PackageDiagnostics>,
    pub deployment_signature: DeploymentSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    WrongPlatform,
    WrongExecutionSemantics,
    EmptyName,
    EmptyProgram,
    InvalidProgram,
    ProgramIdMismatch,
    InterfaceHashMismatch,
    PolicyHashMismatch,
    SchemaHashMismatch,
    AgentSchemaHashMismatch,
    DependenciesHashMismatch,
    InvalidActorArtifacts,
    InvalidRuntimeArtifacts,
    InvalidActorAbi,
    InvalidRuntimeAbi,
    InvalidRuntimeActorAbiRange,
    InvalidRuntimeControlSchema,
    InvalidRuntimeResources,
    UnsupportedRuntimeMigration,
    InvalidRuntimeCapacity,
    UnsupportedActorEntry,
    UnsupportedActorConstructor,
    UnsupportedConstantState,
    UnsupportedActorStorage,
    ArtifactsTooLarge,
    MissingSignature,
    ProducerIdMismatch,
    InvalidSignature,
    WrongKind,
}

impl core::fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid signed package: {self:?}")
    }
}

impl core::error::Error for PackageError {}

impl Package {
    pub fn validate(&self) -> Result<(), PackageError> {
        if self.manifest.platform != crate::service::PLATFORM_ID {
            return Err(PackageError::WrongPlatform);
        }
        if self.manifest.execution_semantics != super::EXECUTION_SEMANTICS_ID {
            return Err(PackageError::WrongExecutionSemantics);
        }
        if self.manifest.name.is_empty() || self.manifest.name.len() > MAX_PACKAGE_NAME_BYTES {
            return Err(PackageError::EmptyName);
        }
        if self.pvm.is_empty() {
            return Err(PackageError::EmptyProgram);
        }
        let task_bytes = self
            .task_dependencies
            .iter()
            .try_fold(0usize, |total, dependency| {
                total.checked_add(dependency.pvm.len())
            });
        let diagnostic_bytes = self.diagnostics.as_ref().map_or(Some(0), |diagnostics| {
            diagnostics
                .elf
                .as_ref()
                .map_or(0, |bytes| bytes.len())
                .checked_add(
                    diagnostics
                        .source_map
                        .as_ref()
                        .map_or(0, |bytes| bytes.len()),
                )
        });
        if self.pvm.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
            || self.generated_interfaces.len() > MAX_PACKAGE_INTERFACES_BYTES
            || self.schemas.len() > MAX_PACKAGE_SCHEMAS_BYTES
            || task_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_TASK_BYTES)
            || diagnostic_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_DIAGNOSTICS_BYTES)
            || self.deployment_signature.public_key.len() > MAX_PACKAGE_SIGNING_KEY_BYTES
            || self.deployment_signature.signature.len() > MAX_PACKAGE_SIGNATURE_BYTES
        {
            return Err(PackageError::ArtifactsTooLarge);
        }
        if !is_valid_program(&self.pvm) {
            return Err(PackageError::InvalidProgram);
        }
        if ProgramId::of_pvm(&self.pvm) != self.manifest.program {
            return Err(PackageError::ProgramIdMismatch);
        }
        if artifact_hash(b"interfaces", &self.generated_interfaces) != self.manifest.interfaces_hash
        {
            return Err(PackageError::InterfaceHashMismatch);
        }
        if artifact_hash(b"role-policies", &self.role_policies) != self.manifest.role_policies_hash
        {
            return Err(PackageError::PolicyHashMismatch);
        }
        if self.role_policies.len() > super::execution::MAX_EXECUTION_POLICY_BYTES {
            return Err(PackageError::InvalidActorArtifacts);
        }
        if artifact_hash(b"schemas", &self.schemas) != self.manifest.schemas_hash {
            return Err(PackageError::SchemaHashMismatch);
        }
        if artifact_hash(b"agent-schema", &self.agent_schema) != self.manifest.agent_schema_hash {
            return Err(PackageError::AgentSchemaHashMismatch);
        }
        if self.agent_schema.len() > super::schema::MAX_ENCODED_BYTES {
            return Err(PackageError::InvalidActorArtifacts);
        }
        if task_dependencies_hash(&self.task_dependencies) != self.manifest.dependencies_hash {
            return Err(PackageError::DependenciesHashMismatch);
        }

        match self.manifest.kind {
            PackageKind::Actor { contract, .. } => {
                if !contract.is_valid() {
                    return Err(PackageError::InvalidActorAbi);
                }
                self.validate_actor_artifacts()?;
            }
            PackageKind::AgentRuntime {
                contract,
                capabilities,
            } => {
                validate_runtime_contract(contract)?;
                if capabilities.max_actors == 0 {
                    return Err(PackageError::InvalidRuntimeCapacity);
                }
                if !self.role_policies.is_empty()
                    || !self.agent_schema.is_empty()
                    || !self.task_dependencies.is_empty()
                {
                    return Err(PackageError::InvalidRuntimeArtifacts);
                }
            }
        }
        if self.deployment_signature.signature.is_empty() {
            return Err(PackageError::MissingSignature);
        }
        if ProducerId::of_public_key(&self.deployment_signature.public_key)
            != self.deployment_signature.producer
        {
            return Err(PackageError::ProducerIdMismatch);
        }
        // Component checks above run first so this exact wire-size check never
        // allocates an attacker-selected generic-service-wire amount.
        if self.encode().len() > MAX_ENCODED_PACKAGE_BYTES {
            return Err(PackageError::ArtifactsTooLarge);
        }
        Ok(())
    }

    fn validate_actor_artifacts(&self) -> Result<(), PackageError> {
        if self.task_dependencies.len() > crate::service::MAX_PACKAGE_TASK_DEPENDENCIES
            || self
                .task_dependencies
                .windows(2)
                .any(|pair| pair[0].binding.task >= pair[1].binding.task)
            || self.task_dependencies.iter().any(|dependency| {
                dependency.pvm.is_empty()
                    || dependency.pvm.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
                    || !is_valid_program(&dependency.pvm)
                    || ProgramId::of_pvm(&dependency.pvm) != dependency.binding.program
                    || Hash(crate::provable::task_blob_hash(&dependency.pvm))
                        != dependency.binding.task
                    || dependency.binding.witness_address == 0
                    || dependency.binding.witness_capacity == 0
                    || dependency
                        .binding
                        .witness_address
                        .checked_add(dependency.binding.witness_capacity)
                        .is_none()
            })
        {
            return Err(PackageError::InvalidActorArtifacts);
        }
        let metadata =
            crate::metadata::decode(&self.schemas).ok_or(PackageError::InvalidActorArtifacts)?;
        let agent_schema =
            super::schema::decode(&self.agent_schema).ok_or(PackageError::InvalidActorArtifacts)?;
        if agent_schema.entry != super::schema::ExecutionEntryKind::AgentActor {
            return Err(PackageError::UnsupportedActorEntry);
        }
        if agent_schema.uses_storage {
            // The standard runtime has no durable row-witness/effect channel.
            // The signed bit makes this a typed pre-install refusal instead
            // of letting a host ECALL fail after actor code has started.
            return Err(PackageError::UnsupportedActorStorage);
        }
        // The initial runtime creates actors through `Actor::create()` and
        // has no authenticated installation-config channel. Accepting a
        // constructor payload or constant field would silently replace its
        // value with `new()` on every lane hydration, so reject both shapes
        // until that lifecycle contract exists.
        if !metadata.constructor.is_empty() {
            return Err(PackageError::UnsupportedActorConstructor);
        }
        if agent_schema
            .fields
            .iter()
            .any(|field| field.persistence == super::FieldPersistence::Constant)
        {
            return Err(PackageError::UnsupportedConstantState);
        }
        if actor_runtime_requirements(&agent_schema, &metadata, !self.task_dependencies.is_empty())
            != match self.manifest.kind {
                PackageKind::Actor { requirements, .. } => requirements,
                PackageKind::AgentRuntime { .. } => {
                    return Err(PackageError::InvalidActorArtifacts);
                }
            }
            || agent_schema.methods.len() != metadata.messages.len()
            || agent_schema.methods.iter().zip(&metadata.messages).any(
                |(agent_method, public_method)| {
                    agent_method.name != public_method.name
                        || (agent_method.mode.write_lane().is_none() != public_method.is_query)
                },
            )
        {
            return Err(PackageError::InvalidActorArtifacts);
        }
        let policies = PackageRolePolicies::decode(&self.role_policies)
            .map_err(|_| PackageError::InvalidActorArtifacts)?;
        let mut expected = PackageRolePolicies::from_metadata(&metadata)
            .map_err(|_| PackageError::InvalidActorArtifacts)?;
        expected.task_dependencies = self
            .task_dependencies
            .iter()
            .map(|dependency| dependency.binding.clone())
            .collect();
        if policies != expected {
            return Err(PackageError::InvalidActorArtifacts);
        }
        Ok(())
    }

    /// Stable identity of signed deployment content. The signature wrapper
    /// and optional diagnostics are not part of deployment identity.
    pub fn deployment_id(&self) -> DeploymentId {
        let mut bytes = Vec::new();
        encode_manifest(&mut Encoder(&mut bytes), &self.manifest);
        bytes.extend_from_slice(&self.pvm);
        DeploymentId(Hash::digest(b"vos/deployment/package", &[&bytes]).0)
    }

    pub fn signing_message(&self) -> [u8; 32] {
        self.deployment_id().0
    }

    /// Offline structural and producer-signature check.
    ///
    /// This result is intentionally not a durable-admission capability. Agent
    /// drivers repeat package verification through their owned
    /// `AgentTrustProvider`, bound to the complete target `AgentConfig`.
    pub fn verify_signature<V: PackageSignatureVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), PackageError> {
        self.validate()?;
        if !verifier.verify(
            &self.deployment_signature.public_key,
            &self.signing_message(),
            &self.deployment_signature.signature,
        ) {
            return Err(PackageError::InvalidSignature);
        }
        Ok(())
    }
}

/// Host trust seam for package signatures. It is deliberately smaller than
/// package policy: production admission can verify cryptography locally and
/// then require a separate authority receipt for the lifecycle operation.
pub trait PackageSignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Default host verifier for the protobuf-encoded Ed25519 public keys emitted
/// by `vosx build`. Bare hosts may provide another implementation without
/// enabling networking.
#[cfg(feature = "network")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519PackageVerifier;

#[cfg(feature = "network")]
impl PackageSignatureVerifier for Ed25519PackageVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(decoded) = libp2p::identity::PublicKey::try_decode_protobuf(public_key) else {
            return false;
        };
        // The package format promises an Ed25519 producer, not merely any
        // key algorithm understood by the host's libp2p feature set. Also
        // require the embedded protobuf to be the canonical encoding so one
        // producer key cannot acquire multiple signed package identities.
        if decoded.encode_protobuf() != public_key {
            return false;
        }
        decoded
            .try_into_ed25519()
            .is_ok_and(|public_key| public_key.verify(message, signature))
    }
}

impl ServiceWire for Package {
    const MAGIC: [u8; 4] = *b"VOSK";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_manifest(&mut encoder, &self.manifest);
        encoder.bytes(&self.pvm);
        encoder.bytes(&self.generated_interfaces);
        encoder.bytes(&self.role_policies);
        encoder.bytes(&self.schemas);
        encoder.bytes(&self.agent_schema);
        encoder.list(&self.task_dependencies, |encoder, dependency| {
            encoder.fixed(&dependency.binding.task.0);
            encoder.fixed(&dependency.binding.program.0);
            encoder.u32(dependency.binding.witness_address);
            encoder.u32(dependency.binding.witness_capacity);
            encoder.bytes(&dependency.pvm);
        });
        encoder.option(&self.diagnostics, |encoder, diagnostics| {
            encoder.option(&diagnostics.elf, |encoder, bytes| encoder.bytes(bytes));
            encoder.option(&diagnostics.source_map, |encoder, bytes| {
                encoder.bytes(bytes)
            });
        });
        encoder.fixed(&self.deployment_signature.producer.0);
        encoder.bytes(&self.deployment_signature.public_key);
        encoder.bytes(&self.deployment_signature.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_ENCODED_PACKAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let manifest = decode_manifest(decoder)?;
        let pvm = decode_bounded_bytes(decoder, super::execution::MAX_EXECUTION_PROGRAM_BYTES)?;
        let generated_interfaces = decode_bounded_bytes(decoder, MAX_PACKAGE_INTERFACES_BYTES)?;
        let role_policies =
            decode_bounded_bytes(decoder, super::execution::MAX_EXECUTION_POLICY_BYTES)?;
        let schemas = decode_bounded_bytes(decoder, MAX_PACKAGE_SCHEMAS_BYTES)?;
        let agent_schema = decode_bounded_bytes(decoder, super::schema::MAX_ENCODED_BYTES)?;
        let dependency_count = decoder.u32()? as usize;
        if dependency_count > crate::service::MAX_PACKAGE_TASK_DEPENDENCIES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut task_bytes = 0usize;
        let mut borrowed_tasks = Vec::with_capacity(dependency_count);
        for _ in 0..dependency_count {
            let binding = crate::service::TaskDependency {
                task: Hash(decoder.fixed()?),
                program: ProgramId(decoder.fixed()?),
                witness_address: decoder.u32()?,
                witness_capacity: decoder.u32()?,
            };
            if binding.witness_address == 0
                || binding.witness_capacity == 0
                || binding
                    .witness_address
                    .checked_add(binding.witness_capacity)
                    .is_none()
            {
                return Err(DecodeError::NonCanonical);
            }
            let pvm = decoder.bytes_ref()?;
            task_bytes = task_bytes
                .checked_add(pvm.len())
                .ok_or(DecodeError::LimitExceeded)?;
            if pvm.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
                || task_bytes > MAX_PACKAGE_TASK_BYTES
            {
                return Err(DecodeError::LimitExceeded);
            }
            borrowed_tasks.push((binding, pvm));
        }
        // The small binding table may be allocated while parsing, but no Task
        // bytecode is copied until the complete aggregate has been checked.
        let task_dependencies = borrowed_tasks
            .into_iter()
            .map(|(binding, pvm)| PackageTaskDependency {
                binding,
                pvm: pvm.to_vec(),
            })
            .collect::<Vec<_>>();
        if task_dependencies
            .windows(2)
            .any(|pair| pair[0].binding.task >= pair[1].binding.task)
        {
            return Err(DecodeError::NonCanonical);
        }
        let diagnostics = if decoder.bool()? {
            let mut diagnostic_bytes = 0usize;
            let elf = decode_bounded_optional_bytes_ref(
                decoder,
                MAX_PACKAGE_DIAGNOSTICS_BYTES,
                &mut diagnostic_bytes,
            )?;
            let source_map = decode_bounded_optional_bytes_ref(
                decoder,
                MAX_PACKAGE_DIAGNOSTICS_BYTES,
                &mut diagnostic_bytes,
            )?;
            Some(PackageDiagnostics {
                elf: elf.map(<[u8]>::to_vec),
                source_map: source_map.map(<[u8]>::to_vec),
            })
        } else {
            None
        };
        Ok(Self {
            manifest,
            pvm,
            generated_interfaces,
            role_policies,
            schemas,
            agent_schema,
            task_dependencies,
            diagnostics,
            deployment_signature: DeploymentSignature {
                producer: ProducerId(decoder.fixed()?),
                public_key: decode_bounded_bytes(decoder, MAX_PACKAGE_SIGNING_KEY_BYTES)?,
                signature: decode_bounded_bytes(decoder, MAX_PACKAGE_SIGNATURE_BYTES)?,
            },
        })
    }
}

fn decode_bounded_bytes(decoder: &mut Decoder<'_>, limit: usize) -> Result<Vec<u8>, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > limit {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(bytes.to_vec())
}

fn decode_bounded_optional_bytes_ref<'a>(
    decoder: &mut Decoder<'a>,
    aggregate_limit: usize,
    aggregate: &mut usize,
) -> Result<Option<&'a [u8]>, DecodeError> {
    if !decoder.bool()? {
        return Ok(None);
    }
    let bytes = decoder.bytes_ref()?;
    *aggregate = aggregate
        .checked_add(bytes.len())
        .ok_or(DecodeError::LimitExceeded)?;
    if *aggregate > aggregate_limit {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(Some(bytes))
}

fn encode_manifest(encoder: &mut Encoder<'_>, manifest: &PackageManifest) {
    encoder.string(&manifest.name);
    encoder.fixed(&manifest.platform.0);
    encoder.fixed(&manifest.execution_semantics.0);
    encode_kind(encoder, manifest.kind);
    encoder.fixed(&manifest.program.0);
    encoder.fixed(&manifest.interfaces_hash.0);
    encoder.fixed(&manifest.role_policies_hash.0);
    encoder.fixed(&manifest.schemas_hash.0);
    encoder.fixed(&manifest.agent_schema_hash.0);
    encoder.fixed(&manifest.dependencies_hash.0);
}

fn decode_manifest(decoder: &mut Decoder<'_>) -> Result<PackageManifest, DecodeError> {
    let name = decoder.bytes_ref()?;
    if name.len() > MAX_PACKAGE_NAME_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(PackageManifest {
        name: String::from_utf8(name.to_vec()).map_err(|_| DecodeError::InvalidUtf8)?,
        platform: Hash(decoder.fixed()?),
        execution_semantics: Hash(decoder.fixed()?),
        kind: decode_kind(decoder)?,
        program: ProgramId(decoder.fixed()?),
        interfaces_hash: Hash(decoder.fixed()?),
        role_policies_hash: Hash(decoder.fixed()?),
        schemas_hash: Hash(decoder.fixed()?),
        agent_schema_hash: Hash(decoder.fixed()?),
        dependencies_hash: Hash(decoder.fixed()?),
    })
}

fn encode_kind(encoder: &mut Encoder<'_>, kind: PackageKind) {
    match kind {
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

fn decode_kind(decoder: &mut Decoder<'_>) -> Result<PackageKind, DecodeError> {
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

fn validate_runtime_contract(contract: RuntimePackageContract) -> Result<(), PackageError> {
    if contract.lifecycle_abi != super::RUNTIME_ABI_ID {
        return Err(PackageError::InvalidRuntimeAbi);
    }
    if !contract.actor_abis.is_valid() {
        return Err(PackageError::InvalidRuntimeActorAbiRange);
    }
    if contract.control_schema != super::contract::CONTROL_SCHEMA_ID {
        return Err(PackageError::InvalidRuntimeControlSchema);
    }
    if !contract.resources.is_valid() {
        return Err(PackageError::InvalidRuntimeResources);
    }
    if !matches!(contract.migration, RuntimeMigrationPolicy::None) {
        return Err(PackageError::UnsupportedRuntimeMigration);
    }
    Ok(())
}

fn encode_requirements(encoder: &mut Encoder<'_>, requirements: RuntimeRequirements) {
    encoder.u8(requirements.lanes.bits());
    encoder.bool(requirements.scheduling);
    encoder.bool(requirements.proofs);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, capabilities: RuntimeCapabilities) {
    encoder.u8(capabilities.lanes.bits());
    encoder.bool(capabilities.scheduling);
    encoder.bool(capabilities.proofs);
    encoder.u32(capabilities.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    Ok(RuntimeCapabilities {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
        max_actors: decoder.u32()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const ACTOR_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        actor_name: "counter",
        messages: &[crate::metadata::MessageMeta {
            name: "increment",
            is_query: false,
            fields: &[],
            returns: "u64",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
            capability: None,
        }],
        constructor: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    const CONSTRUCTOR_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        constructor: &[crate::metadata::FieldMeta {
            name: "initial",
            ty: "u64",
        }],
        ..ACTOR_META
    };

    const ATTESTED_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        messages: &[crate::metadata::MessageMeta {
            attested: true,
            ..ACTOR_META.messages[0]
        }],
        ..ACTOR_META
    };

    const JOB_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        messages: &[crate::metadata::MessageMeta {
            mode: 1,
            ..ACTOR_META.messages[0]
        }],
        ..ACTOR_META
    };

    const ACTOR_SCHEMA: super::super::schema::SchemaMeta = super::super::schema::SchemaMeta {
        uses_storage: false,
        fields: &[super::super::schema::FieldMeta {
            name: "count",
            codec: "counter::u64",
            persistence: super::super::FieldPersistence::State(super::super::StateLane::Linear),
        }],
        methods: &[super::super::schema::MethodMeta {
            name: "increment",
            mode: super::super::MethodMode::Linear,
            explicit: false,
        }],
    };

    const CONSTANT_SCHEMA: super::super::schema::SchemaMeta = super::super::schema::SchemaMeta {
        uses_storage: false,
        fields: &[super::super::schema::FieldMeta {
            name: "unit",
            codec: "counter::String",
            persistence: super::super::FieldPersistence::Constant,
        }],
        methods: ACTOR_SCHEMA.methods,
    };

    const STORAGE_SCHEMA: super::super::schema::SchemaMeta = super::super::schema::SchemaMeta {
        uses_storage: true,
        fields: ACTOR_SCHEMA.fields,
        methods: ACTOR_SCHEMA.methods,
    };

    const STORAGE_FIELDS: &[super::super::schema::StorageFieldMeta] =
        &[super::super::schema::StorageFieldMeta {
            name: "rows",
            type_identity: "counter::StorageMap<u64,u64>",
            lane: super::super::StateLane::Linear,
            prefix: b"rows/",
            committed: false,
            leaf_domain: None,
            node_domain: None,
        }];

    fn signature() -> DeploymentSignature {
        DeploymentSignature {
            producer: ProducerId::of_public_key(b"producer"),
            public_key: b"producer".to_vec(),
            signature: vec![1; 64],
        }
    }

    fn runtime_package() -> Package {
        let pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let interfaces = b"agent-runtime-lifecycle".to_vec();
        let schemas = b"agent-runtime-schema".to_vec();
        Package {
            manifest: PackageManifest {
                name: "standard".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces: interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: signature(),
        }
    }

    fn actor_package(
        metadata: &'static crate::metadata::ActorMeta,
        schema: &'static super::super::schema::SchemaMeta,
        entry: super::super::schema::ExecutionEntryKind,
    ) -> Package {
        actor_package_with_storage(metadata, schema, &[], entry)
    }

    fn actor_package_with_storage(
        metadata: &'static crate::metadata::ActorMeta,
        schema: &'static super::super::schema::SchemaMeta,
        storage: &'static [super::super::schema::StorageFieldMeta],
        entry: super::super::schema::ExecutionEntryKind,
    ) -> Package {
        let pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let (schema_bytes, schema_len) = crate::metadata::encode::<1024>(metadata);
        let schemas = schema_bytes[..schema_len].to_vec();
        let parsed_metadata = crate::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&parsed_metadata)
            .unwrap()
            .encode();
        let (agent_bytes, agent_len) =
            super::super::schema::encode_with_storage::<1024>(schema, storage, entry);
        let agent_schema = agent_bytes[..agent_len].to_vec();
        let requirements = actor_runtime_requirements(
            &super::super::schema::decode(&agent_schema).unwrap(),
            &parsed_metadata,
            false,
        );
        let generated_interfaces = b"counter-interface".to_vec();
        Package {
            manifest: PackageManifest {
                name: "counter".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::Actor {
                    contract: ActorPackageContract::canonical(),
                    requirements,
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &agent_schema),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies,
            schemas,
            agent_schema,
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: signature(),
        }
    }

    #[test]
    fn runtime_package_round_trips_without_an_actor_or_runtime_pin() {
        let package = runtime_package();
        package.validate().unwrap();
        let bytes = package.encode();
        assert_eq!(Package::decode(&bytes).unwrap(), package);
    }

    #[test]
    fn standard_actor_and_runtime_packages_reject_service_semantics() {
        let mut runtime = runtime_package();
        runtime.manifest.execution_semantics = crate::service::EXECUTION_SEMANTICS_ID;
        assert_eq!(
            runtime.validate(),
            Err(PackageError::WrongExecutionSemantics),
        );

        let mut actor = actor_package(
            &ACTOR_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        actor.manifest.execution_semantics = crate::service::EXECUTION_SEMANTICS_ID;
        assert_eq!(actor.validate(), Err(PackageError::WrongExecutionSemantics),);
    }

    #[test]
    fn standard_packages_reject_retired_metering_generations() {
        for retired in [
            crate::service::Hash(*b"vos-pvm-41d31e6-standard-gas-r01"),
            crate::service::Hash(*b"vos-pvm-41d31e6-standard-gas-r02"),
        ] {
            let mut runtime = runtime_package();
            runtime.manifest.execution_semantics = retired;
            assert_eq!(
                runtime.validate(),
                Err(PackageError::WrongExecutionSemantics),
            );

            let mut actor = actor_package(
                &ACTOR_META,
                &ACTOR_SCHEMA,
                super::super::schema::ExecutionEntryKind::AgentActor,
            );
            actor.manifest.execution_semantics = retired;
            assert_eq!(actor.validate(), Err(PackageError::WrongExecutionSemantics));
        }
    }

    #[test]
    fn package_artifact_limits_apply_before_deeper_validation() {
        let mut package = runtime_package();
        package.generated_interfaces = vec![0; MAX_PACKAGE_INTERFACES_BYTES + 1];
        assert_eq!(package.validate(), Err(PackageError::ArtifactsTooLarge));

        let mut package = runtime_package();
        package.diagnostics = Some(PackageDiagnostics {
            elf: Some(vec![0; MAX_PACKAGE_DIAGNOSTICS_BYTES]),
            source_map: Some(vec![0]),
        });
        assert_eq!(package.validate(), Err(PackageError::ArtifactsTooLarge));

        let mut package = actor_package(
            &ACTOR_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        package.task_dependencies = (0..4_u8)
            .map(|index| PackageTaskDependency {
                binding: crate::service::TaskDependency {
                    task: Hash([index + 1; 32]),
                    program: ProgramId([index + 1; 32]),
                    witness_address: 1,
                    witness_capacity: 1,
                },
                pvm: vec![index; MAX_PACKAGE_TASK_BYTES / 4 + 1],
            })
            .collect();
        assert_eq!(package.validate(), Err(PackageError::ArtifactsTooLarge));
    }

    #[test]
    fn package_rejects_structural_programs_the_executor_cannot_run() {
        let mut package = runtime_package();
        package.pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0xff],
                bitmask: vec![1],
            },
        })
        .unwrap();
        package.manifest.program = ProgramId::of_pvm(&package.pvm);
        assert_eq!(package.validate(), Err(PackageError::InvalidProgram));
    }

    #[test]
    fn package_decoder_rejects_oversized_envelope_before_fields() {
        let mut bytes = Vec::with_capacity(MAX_ENCODED_PACKAGE_BYTES + 37);
        bytes.extend_from_slice(&Package::MAGIC);
        bytes.extend_from_slice(&crate::service::PLATFORM_ID.0);
        bytes.resize(MAX_ENCODED_PACKAGE_BYTES + 37, 0);
        assert_eq!(Package::decode(&bytes), Err(DecodeError::LimitExceeded));
    }

    #[test]
    fn runtime_contract_and_capacity_are_signed_and_checked() {
        let mut package = runtime_package();
        let mut contract = RuntimePackageContract::canonical();
        contract.lifecycle_abi = Hash(*b"vos-agent-runtime-abi-20260831r4");
        package.manifest.kind = PackageKind::AgentRuntime {
            contract,
            capabilities: RuntimeCapabilities::standard(),
        };
        assert_eq!(package.validate(), Err(PackageError::InvalidRuntimeAbi));
        package.manifest.kind = PackageKind::AgentRuntime {
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                max_actors: 0,
                ..RuntimeCapabilities::standard()
            },
        };
        assert_eq!(
            package.validate(),
            Err(PackageError::InvalidRuntimeCapacity)
        );

        let mut contract = RuntimePackageContract::canonical();
        contract.actor_abis = ActorAbiRange {
            minimum: 2,
            maximum: 1,
        };
        package.manifest.kind = PackageKind::AgentRuntime {
            contract,
            capabilities: RuntimeCapabilities::standard(),
        };
        assert_eq!(
            package.validate(),
            Err(PackageError::InvalidRuntimeActorAbiRange)
        );

        let mut contract = RuntimePackageContract::canonical();
        contract.control_schema = Hash([7; 32]);
        package.manifest.kind = PackageKind::AgentRuntime {
            contract,
            capabilities: RuntimeCapabilities::standard(),
        };
        assert_eq!(
            package.validate(),
            Err(PackageError::InvalidRuntimeControlSchema)
        );

        let mut contract = RuntimePackageContract::canonical();
        contract.resources.max_runtime_state_bytes = 0;
        package.manifest.kind = PackageKind::AgentRuntime {
            contract,
            capabilities: RuntimeCapabilities::standard(),
        };
        assert_eq!(
            package.validate(),
            Err(PackageError::InvalidRuntimeResources)
        );
    }

    #[test]
    fn actor_abi_is_signed_and_checked_against_the_runtime_range() {
        let mut package = actor_package(
            &ACTOR_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        let canonical_id = package.deployment_id();
        let requirements = match package.manifest.kind {
            PackageKind::Actor { requirements, .. } => requirements,
            PackageKind::AgentRuntime { .. } => unreachable!(),
        };
        package.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract { actor_abi: 2 },
            requirements,
        };
        assert_ne!(package.deployment_id(), canonical_id);
        assert!(!package.manifest.kind.is_compatible_with(
            RuntimePackageContract::canonical(),
            RuntimeCapabilities::standard()
        ));

        package.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract { actor_abi: 0 },
            requirements,
        };
        assert_eq!(package.validate(), Err(PackageError::InvalidActorAbi));
    }

    #[test]
    fn package_decoder_rejects_unknown_migration_policy() {
        let mut bytes = Vec::new();
        encode_runtime_contract(
            &mut Encoder(&mut bytes),
            RuntimePackageContract::canonical(),
        );
        *bytes.last_mut().unwrap() = 1;
        assert_eq!(
            decode_runtime_contract(&mut Decoder::new(&bytes)),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn actor_requirements_do_not_contain_a_runtime_program() {
        let package = runtime_package();
        let requirements = RuntimeRequirements {
            lanes: LaneSet::of(super::super::StateLane::Merge),
            scheduling: false,
            proofs: true,
        };
        let kind = PackageKind::Actor {
            contract: ActorPackageContract::canonical(),
            requirements,
        };
        assert!(!kind.is_compatible_with(
            RuntimePackageContract::canonical(),
            RuntimeCapabilities::standard()
        ));
        assert_ne!(package.manifest.program, ProgramId([0; 32]));
    }

    #[test]
    fn signed_requirements_include_attestation_and_scheduling_contracts() {
        let mut attested = actor_package(
            &ATTESTED_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        assert!(matches!(
            attested.manifest.kind,
            PackageKind::Actor {
                requirements: RuntimeRequirements { proofs: true, .. },
                ..
            }
        ));
        assert!(!attested.manifest.kind.is_compatible_with(
            RuntimePackageContract::canonical(),
            RuntimeCapabilities::standard()
        ));
        attested.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(super::super::StateLane::Linear),
                scheduling: false,
                proofs: false,
            },
        };
        assert_eq!(
            attested.validate(),
            Err(PackageError::InvalidActorArtifacts)
        );

        let mut job = actor_package(
            &JOB_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        assert!(matches!(
            job.manifest.kind,
            PackageKind::Actor {
                requirements: RuntimeRequirements {
                    scheduling: true,
                    ..
                },
                ..
            }
        ));
        assert!(!job.manifest.kind.is_compatible_with(
            RuntimePackageContract::canonical(),
            RuntimeCapabilities::standard()
        ));
        job.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(super::super::StateLane::Linear),
                scheduling: false,
                proofs: false,
            },
        };
        assert_eq!(job.validate(), Err(PackageError::InvalidActorArtifacts));
    }

    #[test]
    fn actor_packages_reject_non_agent_entry_abis() {
        for entry in [
            super::super::schema::ExecutionEntryKind::ServiceActor,
            super::super::schema::ExecutionEntryKind::Task,
        ] {
            let package = actor_package(&ACTOR_META, &ACTOR_SCHEMA, entry);
            assert_eq!(package.validate(), Err(PackageError::UnsupportedActorEntry));
        }
    }

    #[test]
    fn actor_packages_fail_closed_on_unimplemented_install_configuration() {
        let constructor = actor_package(
            &CONSTRUCTOR_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        assert_eq!(
            constructor.validate(),
            Err(PackageError::UnsupportedActorConstructor)
        );

        let constant = actor_package(
            &ACTOR_META,
            &CONSTANT_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        assert_eq!(
            constant.validate(),
            Err(PackageError::UnsupportedConstantState)
        );
    }

    #[test]
    fn actor_packages_reject_signed_storage_use_before_install() {
        let storage = actor_package_with_storage(
            &ACTOR_META,
            &STORAGE_SCHEMA,
            STORAGE_FIELDS,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        assert_eq!(
            storage.validate(),
            Err(PackageError::UnsupportedActorStorage)
        );
    }

    #[test]
    fn offline_signature_check_requires_the_selected_trust_seam() {
        struct Verifier(bool);
        impl PackageSignatureVerifier for Verifier {
            fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
                self.0
            }
        }

        assert_eq!(
            runtime_package().verify_signature(&Verifier(false)),
            Err(PackageError::InvalidSignature)
        );
        assert!(runtime_package().verify_signature(&Verifier(true)).is_ok());
    }

    #[cfg(feature = "network")]
    #[test]
    fn default_verifier_requires_a_canonical_ed25519_producer_key() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let mut package = actor_package(
            &ACTOR_META,
            &ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        package.deployment_signature.public_key = keypair.public().encode_protobuf();
        package.deployment_signature.producer =
            ProducerId::of_public_key(&package.deployment_signature.public_key);
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        assert!(package.verify_signature(&Ed25519PackageVerifier).is_ok());

        package.deployment_signature.signature[0] ^= 0xff;
        assert_eq!(
            package.verify_signature(&Ed25519PackageVerifier),
            Err(PackageError::InvalidSignature),
        );

        package.deployment_signature.signature[0] ^= 0xff;
        // Prost accepts and discards unknown protobuf fields. Reject that
        // alternate byte spelling even though it decodes to the same key.
        package
            .deployment_signature
            .public_key
            .extend_from_slice(&[0x18, 0x00]);
        package.deployment_signature.producer =
            ProducerId::of_public_key(&package.deployment_signature.public_key);
        assert_eq!(
            package.verify_signature(&Ed25519PackageVerifier),
            Err(PackageError::InvalidSignature),
        );
    }
}
