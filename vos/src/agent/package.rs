//! Signed packages for actors and agent runtimes.
//!
//! Actor packages state what they need; they never pin the runtime that will
//! host them. Agent-runtime packages bind the stable lifecycle ABI and state
//! lane capabilities they implement.

use alloc::string::String;
use alloc::vec::Vec;

use super::{LaneSet, PackageKind, RUNTIME_ABI_ID, RuntimeCapabilities, RuntimeRequirements};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{DeploymentId, Hash, ProducerId, ProgramId};
use crate::service::{
    DeploymentSignature, PackageDiagnostics, PackageRolePolicies, PackageTaskDependency,
    artifact_hash, task_dependencies_hash,
};

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
    pub dependencies_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub manifest: PackageManifest,
    pub pvm: Vec<u8>,
    pub generated_interfaces: Vec<u8>,
    pub role_policies: Vec<u8>,
    pub schemas: Vec<u8>,
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
    DependenciesHashMismatch,
    InvalidActorArtifacts,
    InvalidRuntimeArtifacts,
    InvalidRuntimeAbi,
    InvalidRuntimeCapacity,
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
        if self.manifest.execution_semantics != crate::service::EXECUTION_SEMANTICS_ID {
            return Err(PackageError::WrongExecutionSemantics);
        }
        if self.manifest.name.is_empty() {
            return Err(PackageError::EmptyName);
        }
        if self.pvm.is_empty() {
            return Err(PackageError::EmptyProgram);
        }
        if vos_pvm_program::parse_standard_program(&self.pvm).is_none() {
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
        if artifact_hash(b"schemas", &self.schemas) != self.manifest.schemas_hash {
            return Err(PackageError::SchemaHashMismatch);
        }
        if task_dependencies_hash(&self.task_dependencies) != self.manifest.dependencies_hash {
            return Err(PackageError::DependenciesHashMismatch);
        }

        match self.manifest.kind {
            PackageKind::Actor { .. } => self.validate_actor_artifacts()?,
            PackageKind::AgentRuntime { abi, capabilities } => {
                if abi != RUNTIME_ABI_ID {
                    return Err(PackageError::InvalidRuntimeAbi);
                }
                if capabilities.max_actors == 0 {
                    return Err(PackageError::InvalidRuntimeCapacity);
                }
                if !self.role_policies.is_empty() || !self.task_dependencies.is_empty() {
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

    /// Validate package structure and authenticate the producer signature.
    pub fn verify<V: PackageSignatureVerifier>(
        self,
        verifier: &V,
    ) -> Result<VerifiedPackage, PackageError> {
        self.validate()?;
        if !verifier.verify(
            &self.deployment_signature.public_key,
            &self.signing_message(),
            &self.deployment_signature.signature,
        ) {
            return Err(PackageError::InvalidSignature);
        }
        Ok(VerifiedPackage(self))
    }
}

/// Host trust seam for package signatures. It is deliberately smaller than
/// package policy: production admission can verify cryptography locally and
/// then require a separate authority receipt for the lifecycle operation.
pub trait PackageSignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Package whose content and producer signature have both been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPackage(Package);

impl VerifiedPackage {
    pub fn package(&self) -> &Package {
        &self.0
    }

    pub fn into_package(self) -> Package {
        self.0
    }
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
        libp2p::identity::PublicKey::try_decode_protobuf(public_key)
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
        let manifest = decode_manifest(decoder)?;
        let pvm = decoder.bytes()?;
        let generated_interfaces = decoder.bytes()?;
        let role_policies = decoder.bytes()?;
        let schemas = decoder.bytes()?;
        let task_dependencies = decoder.list(|decoder| {
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
            Ok(PackageTaskDependency {
                binding,
                pvm: decoder.bytes()?,
            })
        })?;
        if task_dependencies.len() > crate::service::MAX_PACKAGE_TASK_DEPENDENCIES
            || task_dependencies
                .windows(2)
                .any(|pair| pair[0].binding.task >= pair[1].binding.task)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            manifest,
            pvm,
            generated_interfaces,
            role_policies,
            schemas,
            task_dependencies,
            diagnostics: decoder.option(|decoder| {
                Ok(PackageDiagnostics {
                    elf: decoder.option(Decoder::bytes)?,
                    source_map: decoder.option(Decoder::bytes)?,
                })
            })?,
            deployment_signature: DeploymentSignature {
                producer: ProducerId(decoder.fixed()?),
                public_key: decoder.bytes()?,
                signature: decoder.bytes()?,
            },
        })
    }
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
    encoder.fixed(&manifest.dependencies_hash.0);
}

fn decode_manifest(decoder: &mut Decoder<'_>) -> Result<PackageManifest, DecodeError> {
    Ok(PackageManifest {
        name: decoder.string()?,
        platform: Hash(decoder.fixed()?),
        execution_semantics: Hash(decoder.fixed()?),
        kind: decode_kind(decoder)?,
        program: ProgramId(decoder.fixed()?),
        interfaces_hash: Hash(decoder.fixed()?),
        role_policies_hash: Hash(decoder.fixed()?),
        schemas_hash: Hash(decoder.fixed()?),
        dependencies_hash: Hash(decoder.fixed()?),
    })
}

fn encode_kind(encoder: &mut Encoder<'_>, kind: PackageKind) {
    match kind {
        PackageKind::Actor { requirements } => {
            encoder.u8(0);
            encode_requirements(encoder, requirements);
        }
        PackageKind::AgentRuntime { abi, capabilities } => {
            encoder.u8(1);
            encoder.fixed(&abi.0);
            encode_capabilities(encoder, capabilities);
        }
    }
}

fn decode_kind(decoder: &mut Decoder<'_>) -> Result<PackageKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PackageKind::Actor {
            requirements: decode_requirements(decoder)?,
        }),
        1 => Ok(PackageKind::AgentRuntime {
            abi: Hash(decoder.fixed()?),
            capabilities: decode_capabilities(decoder)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
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
                execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    abi: RUNTIME_ABI_ID,
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces: interfaces,
            role_policies: Vec::new(),
            schemas,
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
    fn runtime_abi_and_capacity_are_signed_and_checked() {
        let mut package = runtime_package();
        package.manifest.kind = PackageKind::AgentRuntime {
            abi: Hash([9; 32]),
            capabilities: RuntimeCapabilities::standard(),
        };
        assert_eq!(package.validate(), Err(PackageError::InvalidRuntimeAbi));
        package.manifest.kind = PackageKind::AgentRuntime {
            abi: RUNTIME_ABI_ID,
            capabilities: RuntimeCapabilities {
                max_actors: 0,
                ..RuntimeCapabilities::standard()
            },
        };
        assert_eq!(
            package.validate(),
            Err(PackageError::InvalidRuntimeCapacity)
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
        let kind = PackageKind::Actor { requirements };
        assert!(kind.is_compatible_with(RuntimeCapabilities::standard()));
        assert_ne!(package.manifest.program, ProgramId([0; 32]));
    }

    #[test]
    fn verified_package_requires_the_signature_trust_seam() {
        struct Verifier(bool);
        impl PackageSignatureVerifier for Verifier {
            fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
                self.0
            }
        }

        assert_eq!(
            runtime_package().verify(&Verifier(false)),
            Err(PackageError::InvalidSignature)
        );
        assert!(runtime_package().verify(&Verifier(true)).is_ok());
    }
}
