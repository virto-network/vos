//! Signed `.vos` v2 packages.
//!
//! Canonical PVM bytes are the executable and proof identity. ELF and source
//! maps are optional diagnostics and are deliberately excluded from
//! [`DeploymentId`] so a registry never has a reason to retranspile them.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::metadata::{ParsedMessage, ParsedMeta};

use super::contracts::{ActorGenesisV2, BlobRefV2, MethodPolicyV2};
use super::identity::{ActorId, DeploymentId, Hash, ProducerId, ProgramId};
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

/// Canonical generated authorization artifact carried by `.vos` v2.
///
/// The package stores this exact wire value rather than an opaque policy file.
/// Registries and installers can therefore prove that every installed method
/// policy was derived from the signed schema and source annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRolePoliciesV2 {
    pub methods: Vec<MethodPolicyV2>,
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
    InvalidSchema,
    InvalidRolePolicies,
    PolicySchemaMismatch,
    CrdtMetadataMismatch,
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
        let metadata = crate::metadata::decode(&self.schemas).ok_or(PackageError::InvalidSchema)?;
        let policies = PackageRolePoliciesV2::decode(&self.role_policies)
            .map_err(|_| PackageError::InvalidRolePolicies)?;
        let expected = PackageRolePoliciesV2::from_metadata(&metadata)?;
        if policies != expected {
            return Err(PackageError::PolicySchemaMismatch);
        }
        if self.manifest.crdt != metadata.crdt {
            return Err(PackageError::CrdtMetadataMismatch);
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

    /// Build the exact actor descriptor accepted by guest-owned installation.
    /// No caller can substitute hand-authored method policies after package
    /// validation: the rows come from the signed canonical policy artifact.
    pub fn actor_genesis(
        &self,
        actor: ActorId,
        name: String,
        parent: Option<ActorId>,
        initial_state: BlobRefV2,
    ) -> Result<ActorGenesisV2, PackageError> {
        self.validate()?;
        let policies = PackageRolePoliciesV2::decode(&self.role_policies)
            .map_err(|_| PackageError::InvalidRolePolicies)?;
        Ok(ActorGenesisV2 {
            actor,
            name,
            parent,
            program: self.manifest.actor_program,
            initial_state,
            crdt: self.manifest.crdt,
            methods: policies.methods,
        })
    }
}

impl PackageRolePoliciesV2 {
    pub fn from_metadata(metadata: &ParsedMeta) -> Result<Self, PackageError> {
        let mut methods = metadata
            .messages
            .iter()
            .map(|message| {
                let policy = match message.space_role {
                    Some(role) => {
                        space_role_policy_hash(role).ok_or(PackageError::InvalidRolePolicies)?
                    }
                    None => public_policy_hash(),
                };
                Ok(MethodPolicyV2 {
                    method: message.name.clone(),
                    schema: method_schema_hash(message),
                    policy,
                    public: message.space_role.is_none(),
                    attested: message.attested,
                })
            })
            .collect::<Result<Vec<_>, PackageError>>()?;
        methods.sort_by(|left, right| left.method.cmp(&right.method));
        if methods
            .windows(2)
            .any(|pair| pair[0].method == pair[1].method)
        {
            return Err(PackageError::InvalidRolePolicies);
        }
        Ok(Self { methods })
    }
}

/// Commitment to one method's argument/reply schema. Operational metadata
/// such as documentation, timeout, CLI exposure, and job scheduling mode is
/// deliberately excluded.
pub fn method_schema_hash(message: &ParsedMessage) -> Hash {
    let mut bytes = Vec::new();
    let mut encoder = Encoder(&mut bytes);
    encoder.string(&message.name);
    encoder.bool(message.is_query);
    encoder.list(&message.fields, |encoder, field| {
        encoder.string(&field.name);
        encoder.string(&field.ty);
    });
    encoder.string(&message.returns);
    Hash::digest(b"vos/method-schema/v2", &[&bytes])
}

/// Stable public-method predicate used even for attested public methods, so
/// an attestation statement never carries an ambiguous zero policy.
pub fn public_policy_hash() -> Hash {
    Hash::digest(b"vos/public-policy/v2", &[])
}

/// Stable predicate for a direct `SpaceRole` threshold. Unknown role bytes
/// are rejected instead of entering deployment identity.
pub fn space_role_policy_hash(required_role: u8) -> Option<Hash> {
    crate::SpaceRole::from_u8(required_role).map(|_| {
        Hash::digest(
            b"vos/space-role-policy/v2",
            &[core::slice::from_ref(&required_role)],
        )
    })
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

impl V2Wire for PackageRolePoliciesV2 {
    const MAGIC: [u8; 4] = *b"VRP2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        Encoder(out).list(&self.methods, |encoder, method| {
            encoder.bytes(&method.encode())
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let methods = decoder.list(|decoder| MethodPolicyV2::decode(&decoder.bytes()?))?;
        if methods
            .windows(2)
            .any(|pair| pair[0].method >= pair[1].method)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self { methods })
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

    use crate::metadata::{ActorMeta, MessageMeta};

    use super::*;

    const META: ActorMeta = ActorMeta {
        actor_name: "counter",
        messages: &[
            MessageMeta {
                name: "increment",
                is_query: false,
                fields: &[],
                returns: "u64",
                doc: "",
                timeout_ms: 0,
                mode: 0,
                attested: false,
                space_role: None,
            },
            MessageMeta {
                name: "is_positive",
                is_query: true,
                fields: &[],
                returns: "bool",
                doc: "",
                timeout_ms: 0,
                mode: 0,
                attested: true,
                space_role: Some(crate::SpaceRole::Member as u8),
            },
        ],
        constructor: &[],
        kind: 0,
        caps: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
    };

    fn schema_and_policies() -> (Vec<u8>, Vec<u8>) {
        let (buffer, length) = crate::metadata::encode::<512>(&META);
        let schemas = buffer[..length].to_vec();
        let metadata = crate::metadata::decode(&schemas).unwrap();
        let policies = PackageRolePoliciesV2::from_metadata(&metadata)
            .unwrap()
            .encode();
        (schemas, policies)
    }

    fn package() -> VosPackageV2 {
        let pvm = vec![1, 2, 3, 4];
        let interfaces = b"interface".to_vec();
        let (schemas, policies) = schema_and_policies();
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
    fn method_policies_are_derived_from_schema_and_annotations() {
        let package = package();
        let policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
        assert_eq!(policies.methods.len(), 2);

        let increment = &policies.methods[0];
        assert_eq!(increment.method, "increment");
        assert!(increment.public);
        assert!(!increment.attested);
        assert_eq!(increment.policy, public_policy_hash());

        let is_positive = &policies.methods[1];
        assert_eq!(is_positive.method, "is_positive");
        assert!(!is_positive.public);
        assert!(is_positive.attested);
        assert_eq!(
            is_positive.policy,
            space_role_policy_hash(crate::SpaceRole::Member as u8).unwrap()
        );
    }

    #[test]
    fn package_rejects_policy_schema_drift() {
        let mut package = package();
        let mut policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
        policies.methods[1].attested = false;
        package.role_policies = policies.encode();
        package.manifest.role_policies_hash =
            artifact_hash(b"role-policies", &package.role_policies);
        assert_eq!(package.validate(), Err(PackageError::PolicySchemaMismatch));
    }

    #[test]
    fn guest_install_descriptor_uses_only_signed_package_policies() {
        let package = package();
        let actor = ActorId([7; 32]);
        let state = BlobRefV2::of_bytes(b"initial state");
        let genesis = package
            .actor_genesis(actor, "counter".into(), None, state.clone())
            .unwrap();
        let policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
        assert_eq!(genesis.actor, actor);
        assert_eq!(genesis.program, package.manifest.actor_program);
        assert_eq!(genesis.initial_state, state);
        assert_eq!(genesis.methods, policies.methods);
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
