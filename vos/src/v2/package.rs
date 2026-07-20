//! Signed `.vos` v2 packages.
//!
//! Canonical PVM bytes are the executable and proof identity. ELF and source
//! maps are optional diagnostics and are deliberately excluded from
//! [`DeploymentId`] so a registry never has a reason to retranspile them.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::identity::{DeploymentId, Hash, ProducerId, ProgramId};
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifestV2 {
    pub name: String,
    pub version: String,
    pub service_abi: u16,
    pub snapshot_version: u16,
    pub execution_semantics: Hash,
    pub service_program: ProgramId,
    pub actor_program: ProgramId,
    pub crdt: bool,
    pub interfaces_hash: Hash,
    pub role_policies_hash: Hash,
    pub schemas_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDiagnosticsV2 {
    pub elf: Option<Vec<u8>>,
    pub source_map: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentSignatureV2 {
    pub producer: ProducerId,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VosPackageV2 {
    pub manifest: PackageManifestV2,
    pub actor_pvm: Vec<u8>,
    pub generated_interfaces: Vec<u8>,
    pub role_policies: Vec<u8>,
    pub schemas: Vec<u8>,
    pub diagnostics: Option<PackageDiagnosticsV2>,
    pub deployment_signature: DeploymentSignatureV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageError {
    WrongAbi,
    WrongSnapshotVersion,
    WrongExecutionSemantics,
    EmptyName,
    EmptyProgram,
    ProgramIdMismatch,
    InterfaceHashMismatch,
    PolicyHashMismatch,
    SchemaHashMismatch,
    MissingSignature,
    ProducerIdMismatch,
}

/// Signature seam used by deployment registries. Implementations are pinned
/// host infrastructure; package validation itself remains `no_std` and does
/// not select a cryptographic library.
pub trait DeploymentSignatureVerifierV2 {
    fn verify(&self, public_key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool;
}

impl<F> DeploymentSignatureVerifierV2 for F
where
    F: Fn(&[u8], &[u8; 32], &[u8]) -> bool,
{
    fn verify(&self, public_key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        self(public_key, message, signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageRegistrationErrorV2 {
    NonCanonicalPackage,
    InvalidPackage(PackageError),
    WrongServiceProgram,
    InvalidSignature,
    TagConflict,
    DivergentDeploymentBytes,
}

impl core::fmt::Display for PackageRegistrationErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot register .vos v2 deployment: {self:?}")
    }
}

impl core::error::Error for PackageRegistrationErrorV2 {}

/// Exact-byte registry for signed v2 deployments.
///
/// A registry never accepts an ELF and never retranspiles. The canonical actor
/// PVM can be read from the retained package, while JIT/proving derivatives are
/// external caches keyed by its `ProgramId`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentRegistryV2 {
    exact_packages: BTreeMap<DeploymentId, Vec<u8>>,
    tags: BTreeMap<(String, String), DeploymentId>,
}

impl DeploymentRegistryV2 {
    pub fn register(
        &mut self,
        exact_bytes: &[u8],
        expected_service_program: ProgramId,
        verifier: &impl DeploymentSignatureVerifierV2,
    ) -> Result<DeploymentId, PackageRegistrationErrorV2> {
        let package = VosPackageV2::decode(exact_bytes)
            .map_err(|_| PackageRegistrationErrorV2::NonCanonicalPackage)?;
        package
            .validate()
            .map_err(PackageRegistrationErrorV2::InvalidPackage)?;
        if package.encode() != exact_bytes {
            return Err(PackageRegistrationErrorV2::NonCanonicalPackage);
        }
        if package.manifest.service_program != expected_service_program {
            return Err(PackageRegistrationErrorV2::WrongServiceProgram);
        }
        if !verifier.verify(
            &package.deployment_signature.public_key,
            &package.signing_message(),
            &package.deployment_signature.signature,
        ) {
            return Err(PackageRegistrationErrorV2::InvalidSignature);
        }

        let deployment = package.deployment_id();
        let tag = (
            package.manifest.name.clone(),
            package.manifest.version.clone(),
        );
        if let Some(existing) = self.tags.get(&tag)
            && *existing != deployment
        {
            return Err(PackageRegistrationErrorV2::TagConflict);
        }
        if let Some(existing) = self.exact_packages.get(&deployment) {
            if existing.as_slice() != exact_bytes {
                return Err(PackageRegistrationErrorV2::DivergentDeploymentBytes);
            }
            return Ok(deployment);
        }

        self.exact_packages.insert(deployment, exact_bytes.to_vec());
        self.tags.insert(tag, deployment);
        Ok(deployment)
    }

    pub fn exact_package(&self, deployment: DeploymentId) -> Option<&[u8]> {
        self.exact_packages.get(&deployment).map(Vec::as_slice)
    }

    pub fn resolve(&self, name: &str, version: &str) -> Option<DeploymentId> {
        self.tags
            .get(&(String::from(name), String::from(version)))
            .copied()
    }

    pub fn actor_pvm(&self, deployment: DeploymentId) -> Option<Vec<u8>> {
        VosPackageV2::decode(self.exact_package(deployment)?)
            .ok()
            .map(|package| package.actor_pvm)
    }
}

impl core::fmt::Display for PackageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid .vos v2 package: {self:?}")
    }
}

impl core::error::Error for PackageError {}

impl VosPackageV2 {
    pub fn validate(&self) -> Result<(), PackageError> {
        if self.manifest.service_abi != super::ABI_VERSION {
            return Err(PackageError::WrongAbi);
        }
        if self.manifest.snapshot_version != super::SNAPSHOT_VERSION {
            return Err(PackageError::WrongSnapshotVersion);
        }
        if self.manifest.execution_semantics != super::EXECUTION_SEMANTICS_ID {
            return Err(PackageError::WrongExecutionSemantics);
        }
        if self.manifest.name.is_empty() || self.manifest.version.is_empty() {
            return Err(PackageError::EmptyName);
        }
        if self.actor_pvm.is_empty() {
            return Err(PackageError::EmptyProgram);
        }
        if ProgramId::of_pvm(&self.actor_pvm) != self.manifest.actor_program {
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

    /// Identity of the signed deployment content. Diagnostics and the
    /// signature wrapper are not package identity; all authoritative
    /// interfaces/policies/schemas are bound by hashes in the manifest.
    pub fn deployment_id(&self) -> DeploymentId {
        let mut bytes = Vec::new();
        encode_manifest(&mut Encoder(&mut bytes), &self.manifest);
        bytes.extend_from_slice(&self.actor_pvm);
        DeploymentId(crate::crypto::blake2b_hash::<32>(
            b"vos/deployment/v2",
            &[&bytes, &self.manifest.service_abi.to_le_bytes()],
        ))
    }

    /// Bytes covered by a deployment signature.
    pub fn signing_message(&self) -> [u8; 32] {
        self.deployment_id().0
    }
}

pub fn artifact_hash(kind: &[u8], bytes: &[u8]) -> Hash {
    Hash(crate::crypto::blake2b_hash::<32>(
        b"vos/package-artifact/v2",
        &[kind, bytes],
    ))
}

impl V2Wire for VosPackageV2 {
    const MAGIC: [u8; 4] = *b"VOSP";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encode_manifest(&mut encoder, &self.manifest);
        encoder.bytes(&self.actor_pvm);
        encoder.bytes(&self.generated_interfaces);
        encoder.bytes(&self.role_policies);
        encoder.bytes(&self.schemas);
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
        Ok(Self {
            manifest: decode_manifest(decoder)?,
            actor_pvm: decoder.bytes()?,
            generated_interfaces: decoder.bytes()?,
            role_policies: decoder.bytes()?,
            schemas: decoder.bytes()?,
            diagnostics: decoder.option(|decoder| {
                Ok(PackageDiagnosticsV2 {
                    elf: decoder.option(Decoder::bytes)?,
                    source_map: decoder.option(Decoder::bytes)?,
                })
            })?,
            deployment_signature: DeploymentSignatureV2 {
                producer: ProducerId(decoder.fixed()?),
                public_key: decoder.bytes()?,
                signature: decoder.bytes()?,
            },
        })
    }
}

fn encode_manifest(encoder: &mut Encoder<'_>, manifest: &PackageManifestV2) {
    encoder.string(&manifest.name);
    encoder.string(&manifest.version);
    encoder.u16(manifest.service_abi);
    encoder.u16(manifest.snapshot_version);
    encoder.fixed(&manifest.execution_semantics.0);
    encoder.fixed(&manifest.service_program.0);
    encoder.fixed(&manifest.actor_program.0);
    encoder.bool(manifest.crdt);
    encoder.fixed(&manifest.interfaces_hash.0);
    encoder.fixed(&manifest.role_policies_hash.0);
    encoder.fixed(&manifest.schemas_hash.0);
}

fn decode_manifest(decoder: &mut Decoder<'_>) -> Result<PackageManifestV2, DecodeError> {
    Ok(PackageManifestV2 {
        name: decoder.string()?,
        version: decoder.string()?,
        service_abi: decoder.u16()?,
        snapshot_version: decoder.u16()?,
        execution_semantics: Hash(decoder.fixed()?),
        service_program: ProgramId(decoder.fixed()?),
        actor_program: ProgramId(decoder.fixed()?),
        crdt: decoder.bool()?,
        interfaces_hash: Hash(decoder.fixed()?),
        role_policies_hash: Hash(decoder.fixed()?),
        schemas_hash: Hash(decoder.fixed()?),
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn package() -> VosPackageV2 {
        let pvm = vec![1, 2, 3, 4];
        let interfaces = b"interface".to_vec();
        let policies = b"policy".to_vec();
        let schemas = b"schema".to_vec();
        VosPackageV2 {
            manifest: PackageManifestV2 {
                name: "counter".into(),
                version: "2.0.0".into(),
                service_abi: super::super::ABI_VERSION,
                snapshot_version: super::super::SNAPSHOT_VERSION,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                service_program: ProgramId([9; 32]),
                actor_program: ProgramId::of_pvm(&pvm),
                crdt: false,
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
            },
            actor_pvm: pvm,
            generated_interfaces: interfaces,
            role_policies: policies,
            schemas,
            diagnostics: None,
            deployment_signature: DeploymentSignatureV2 {
                producer: ProducerId::of_public_key(b"key"),
                public_key: b"key".to_vec(),
                signature: vec![8; 64],
            },
        }
    }

    #[test]
    fn package_roundtrip_is_deterministic() {
        let package = package();
        package.validate().unwrap();
        let bytes = package.encode();
        let decoded = VosPackageV2::decode(&bytes).unwrap();
        assert_eq!(decoded, package);
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(decoded.deployment_id(), package.deployment_id());
    }

    #[test]
    fn program_identity_ignores_diagnostics_but_not_pvm_bytes() {
        let mut package = package();
        let id = package.deployment_id();
        package.diagnostics = Some(PackageDiagnosticsV2 {
            elf: Some(vec![42]),
            source_map: None,
        });
        assert_eq!(id, package.deployment_id());
        package.actor_pvm.push(5);
        assert_eq!(package.validate(), Err(PackageError::ProgramIdMismatch));
        assert_ne!(id, package.deployment_id());
    }

    #[test]
    fn registry_retains_exact_signed_bytes_and_never_accepts_an_elf() {
        let package = package();
        let bytes = package.encode();
        let service_program = package.manifest.service_program;
        let verifier = |key: &[u8], message: &[u8; 32], signature: &[u8]| {
            key == b"key" && *message == package.signing_message() && signature == [8; 64]
        };
        let mut registry = DeploymentRegistryV2::default();
        let deployment = registry
            .register(&bytes, service_program, &verifier)
            .unwrap();
        assert_eq!(registry.exact_package(deployment), Some(bytes.as_slice()));
        assert_eq!(
            registry.actor_pvm(deployment),
            Some(package.actor_pvm.clone())
        );
        assert_eq!(registry.resolve("counter", "2.0.0"), Some(deployment));
        assert_eq!(
            registry.register(&bytes, service_program, &verifier),
            Ok(deployment),
            "an exact retry is idempotent"
        );
        assert_eq!(
            registry.register(b"ELF bytes", service_program, &verifier),
            Err(PackageRegistrationErrorV2::NonCanonicalPackage)
        );
    }

    #[test]
    fn registry_rejects_bad_signatures_tags_and_same_id_byte_drift() {
        let package = package();
        let service_program = package.manifest.service_program;
        let accepts = |_: &[u8], _: &[u8; 32], signature: &[u8]| signature == [8; 64];
        let rejects = |_: &[u8], _: &[u8; 32], _: &[u8]| false;
        let mut registry = DeploymentRegistryV2::default();
        assert_eq!(
            registry.register(&package.encode(), service_program, &rejects),
            Err(PackageRegistrationErrorV2::InvalidSignature)
        );
        let deployment = registry
            .register(&package.encode(), service_program, &accepts)
            .unwrap();

        let mut diagnostic_drift = package.clone();
        diagnostic_drift.diagnostics = Some(PackageDiagnosticsV2 {
            elf: Some(vec![99]),
            source_map: None,
        });
        assert_eq!(diagnostic_drift.deployment_id(), deployment);
        assert_eq!(
            registry.register(&diagnostic_drift.encode(), service_program, &accepts),
            Err(PackageRegistrationErrorV2::DivergentDeploymentBytes)
        );

        let mut conflicting = package;
        conflicting.actor_pvm.push(5);
        conflicting.manifest.actor_program = ProgramId::of_pvm(&conflicting.actor_pvm);
        conflicting.deployment_signature.signature = vec![8; 64];
        assert_eq!(
            registry.register(&conflicting.encode(), service_program, &accepts),
            Err(PackageRegistrationErrorV2::TagConflict)
        );
    }
}
