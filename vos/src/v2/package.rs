//! Signed `.vos` v2 packages.
//!
//! Canonical PVM bytes are the executable and proof identity. ELF and source
//! maps are optional diagnostics and are deliberately excluded from
//! [`DeploymentId`] so a registry never has a reason to retranspile them.

use alloc::string::String;
use alloc::vec::Vec;

use crate::metadata::{ParsedMessage, ParsedMeta};

use super::contracts::{ActorGenesisV2, BlobRefV2, MethodPolicyV2, TaskDependencyV2};
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
    pub task_dependencies_hash: Hash,
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
    /// Content-addressed pure Task programs this actor may invoke. The exact
    /// PVM and witness window are signed package content; installation retains
    /// only the compact binding in guest-owned actor state and places the PVM
    /// in the recoverable service program catalog.
    pub task_dependencies: Vec<PackageTaskDependencyV2>,
    pub diagnostics: Option<PackageDiagnosticsV2>,
    pub deployment_signature: DeploymentSignatureV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTaskDependencyV2 {
    pub binding: TaskDependencyV2,
    pub pvm: Vec<u8>,
}

/// Canonical generated authorization artifact carried by `.vos` v2.
///
/// The package stores this exact wire value rather than an opaque policy file.
/// Registries and installers can therefore prove that every installed method
/// policy was derived from the signed schema and source annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRolePoliciesV2 {
    pub methods: Vec<MethodPolicyV2>,
    /// Compact Task bindings duplicated from the package dependency artifact.
    /// This exact signed policy wire is retained in guest-owned actor state,
    /// so scheduling after restart never needs the original `.vos` envelope.
    pub task_dependencies: Vec<TaskDependencyV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageError {
    WrongAbi,
    WrongSnapshotVersion,
    WrongExecutionSemantics,
    EmptyName,
    EmptyProgram,
    ServiceProgramMismatch,
    ProgramIdMismatch,
    InterfaceHashMismatch,
    PolicyHashMismatch,
    SchemaHashMismatch,
    TaskDependenciesHashMismatch,
    InvalidTaskDependencies,
    InvalidSchema,
    InvalidRolePolicies,
    PolicySchemaMismatch,
    CrdtMetadataMismatch,
    InvalidActorName,
    MissingSignature,
    ProducerIdMismatch,
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
        if self.manifest.service_program != super::VOS_SERVICE_PROGRAM_ID {
            return Err(PackageError::ServiceProgramMismatch);
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
        if task_dependencies_hash(&self.task_dependencies) != self.manifest.task_dependencies_hash {
            return Err(PackageError::TaskDependenciesHashMismatch);
        }
        if self.task_dependencies.len() > super::MAX_PACKAGE_TASK_DEPENDENCIES
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
            return Err(PackageError::InvalidTaskDependencies);
        }
        let metadata = crate::metadata::decode(&self.schemas).ok_or(PackageError::InvalidSchema)?;
        let policies = PackageRolePoliciesV2::decode(&self.role_policies)
            .map_err(|_| PackageError::InvalidRolePolicies)?;
        let expected = PackageRolePoliciesV2::from_metadata(&metadata)?;
        let package_bindings = self
            .task_dependencies
            .iter()
            .map(|dependency| dependency.binding.clone())
            .collect::<Vec<_>>();
        if policies.methods != expected.methods || policies.task_dependencies != package_bindings {
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
        if name.is_empty() || name.len() > super::MAX_ACTOR_NAME_BYTES {
            return Err(PackageError::InvalidActorName);
        }
        Ok(ActorGenesisV2 {
            actor,
            name,
            parent,
            producer: self.deployment_signature.producer,
            deployment: self.deployment_id(),
            program: self.manifest.actor_program,
            initial_state,
            crdt: self.manifest.crdt,
            role_policies: self.role_policies.clone(),
        })
    }
}

impl PackageRolePoliciesV2 {
    pub fn from_metadata(metadata: &ParsedMeta) -> Result<Self, PackageError> {
        let mut methods = metadata
            .messages
            .iter()
            .map(|message| {
                let policy = method_role_policy_hash(message.space_role, message.actor_role)
                    .ok_or(PackageError::InvalidRolePolicies)?;
                Ok(MethodPolicyV2 {
                    method: message.name.clone(),
                    schema: method_schema_hash(message),
                    policy,
                    public: message.space_role.is_none() && message.actor_role.is_none(),
                    attested: message.attested,
                    space_role: message.space_role,
                    actor_role: message.actor_role,
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
        Ok(Self {
            methods,
            task_dependencies: Vec::new(),
        })
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

/// Stable predicate for the conjunction of direct space-wide and actor-local
/// thresholds. Unknown space-role bytes are rejected before they can enter
/// deployment identity; actor-role bytes are interpreted by the pinned actor
/// program's `RoleByte` implementation.
pub fn method_role_policy_hash(space_role: Option<u8>, actor_role: Option<u8>) -> Option<Hash> {
    if let Some(role) = space_role {
        crate::SpaceRole::from_u8(role)?;
    }
    if actor_role == Some(u8::MAX) {
        return None;
    }
    if space_role.is_none() && actor_role.is_none() {
        return Some(public_policy_hash());
    }
    let bytes = [
        u8::from(space_role.is_some()),
        space_role.unwrap_or_default(),
        u8::from(actor_role.is_some()),
        actor_role.unwrap_or_default(),
    ];
    Some(Hash::digest(b"vos/method-role-policy/v2", &[&bytes]))
}

pub fn space_role_policy_hash(required_role: u8) -> Option<Hash> {
    method_role_policy_hash(Some(required_role), None)
}

pub fn artifact_hash(kind: &[u8], bytes: &[u8]) -> Hash {
    Hash(crate::crypto::blake2b_hash::<32>(
        b"vos/package-artifact/v2",
        &[kind, bytes],
    ))
}

/// Commitment used by the signed manifest for the complete canonical Task
/// dependency artifact, including executable bytes and witness layout.
pub fn task_dependencies_hash(dependencies: &[PackageTaskDependencyV2]) -> Hash {
    let mut bytes = Vec::new();
    let mut encoder = Encoder(&mut bytes);
    encoder.list(dependencies, |encoder, dependency| {
        encode_task_dependency(encoder, &dependency.binding);
        encoder.bytes(&dependency.pvm);
    });
    artifact_hash(b"task-dependencies", &bytes)
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
        encoder.list(&self.task_dependencies, |encoder, dependency| {
            encode_task_dependency(encoder, &dependency.binding);
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
        Ok(Self {
            manifest: decode_manifest(decoder)?,
            actor_pvm: decoder.bytes()?,
            generated_interfaces: decoder.bytes()?,
            role_policies: decoder.bytes()?,
            schemas: decoder.bytes()?,
            task_dependencies: decode_package_task_dependencies(decoder)?,
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
        let mut encoder = Encoder(out);
        encoder.list(&self.methods, |encoder, method| {
            encoder.bytes(&method.encode())
        });
        encoder.list(&self.task_dependencies, |encoder, dependency| {
            encode_task_dependency(encoder, dependency)
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
        let task_dependencies = decode_task_dependencies(decoder)?;
        if task_dependencies
            .windows(2)
            .any(|pair| pair[0].task >= pair[1].task)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            methods,
            task_dependencies,
        })
    }
}

fn decode_task_dependencies(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<TaskDependencyV2>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > super::MAX_PACKAGE_TASK_DEPENDENCIES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut dependencies = Vec::with_capacity(len);
    for _ in 0..len {
        dependencies.push(decode_task_dependency(decoder)?);
    }
    Ok(dependencies)
}

fn decode_package_task_dependencies(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<PackageTaskDependencyV2>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > super::MAX_PACKAGE_TASK_DEPENDENCIES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut dependencies = Vec::with_capacity(len);
    for _ in 0..len {
        dependencies.push(PackageTaskDependencyV2 {
            binding: decode_task_dependency(decoder)?,
            pvm: decoder.bytes()?,
        });
    }
    Ok(dependencies)
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
    encoder.fixed(&manifest.task_dependencies_hash.0);
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
        task_dependencies_hash: Hash(decoder.fixed()?),
    })
}

fn encode_task_dependency(encoder: &mut Encoder<'_>, dependency: &TaskDependencyV2) {
    encoder.fixed(&dependency.task.0);
    encoder.fixed(&dependency.program.0);
    encoder.u32(dependency.witness_address);
    encoder.u32(dependency.witness_capacity);
}

fn decode_task_dependency(decoder: &mut Decoder<'_>) -> Result<TaskDependencyV2, DecodeError> {
    let value = TaskDependencyV2 {
        task: Hash(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        witness_address: decoder.u32()?,
        witness_capacity: decoder.u32()?,
    };
    if value.witness_address == 0
        || value.witness_capacity == 0
        || value
            .witness_address
            .checked_add(value.witness_capacity)
            .is_none()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
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
                actor_role: None,
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
                actor_role: Some(2),
            },
        ],
        constructor: &[],
        kind: 0,
        caps: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
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
        let pvm = grey_transpiler::assembler::Assembler::new().build();
        let interfaces = b"interface".to_vec();
        let (schemas, policies) = schema_and_policies();
        VosPackageV2 {
            manifest: PackageManifestV2 {
                name: "counter".into(),
                version: "2.0.0".into(),
                service_abi: super::super::ABI_VERSION,
                snapshot_version: super::super::SNAPSHOT_VERSION,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                service_program: super::super::VOS_SERVICE_PROGRAM_ID,
                actor_program: ProgramId::of_pvm(&pvm),
                crdt: false,
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                task_dependencies_hash: task_dependencies_hash(&[]),
            },
            actor_pvm: pvm,
            generated_interfaces: interfaces,
            role_policies: policies,
            schemas,
            task_dependencies: vec![],
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
    fn task_dependencies_are_signed_canonical_package_content() {
        let mut package = package();
        let task_pvm = grey_transpiler::assembler::Assembler::new().build();
        let binding = TaskDependencyV2 {
            task: Hash(crate::provable::task_blob_hash(&task_pvm)),
            program: ProgramId::of_pvm(&task_pvm),
            witness_address: 0x1_0000,
            witness_capacity: 4096,
        };
        package.task_dependencies = vec![PackageTaskDependencyV2 {
            binding: binding.clone(),
            pvm: task_pvm,
        }];
        let mut policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
        policies.task_dependencies = vec![binding];
        package.role_policies = policies.encode();
        package.manifest.role_policies_hash =
            artifact_hash(b"role-policies", &package.role_policies);
        package.manifest.task_dependencies_hash =
            task_dependencies_hash(&package.task_dependencies);

        package.validate().unwrap();
        let decoded = VosPackageV2::decode(&package.encode()).unwrap();
        assert_eq!(decoded.task_dependencies, package.task_dependencies);
        assert_eq!(decoded.deployment_id(), package.deployment_id());

        let mut tampered = package;
        tampered.task_dependencies[0].pvm.push(0);
        assert_eq!(
            tampered.validate(),
            Err(PackageError::TaskDependenciesHashMismatch)
        );
        tampered.manifest.task_dependencies_hash =
            task_dependencies_hash(&tampered.task_dependencies);
        assert_eq!(
            tampered.validate(),
            Err(PackageError::InvalidTaskDependencies)
        );
    }

    #[test]
    fn task_dependency_wires_reject_an_oversized_count_before_items() {
        let bytes = ((super::super::MAX_PACKAGE_TASK_DEPENDENCIES + 1) as u32).to_le_bytes();
        assert_eq!(
            decode_task_dependencies(&mut Decoder::new(&bytes)),
            Err(DecodeError::LimitExceeded)
        );
        assert_eq!(
            decode_package_task_dependencies(&mut Decoder::new(&bytes)),
            Err(DecodeError::LimitExceeded)
        );
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
            is_positive.space_role,
            Some(crate::SpaceRole::Member.as_u8())
        );
        assert_eq!(is_positive.actor_role, Some(2));
        assert_eq!(
            is_positive.policy,
            method_role_policy_hash(Some(crate::SpaceRole::Member.as_u8()), Some(2)).unwrap()
        );

        let mut metadata = crate::metadata::decode(&package.schemas).unwrap();
        let increment_meta = metadata
            .messages
            .iter_mut()
            .find(|message| message.name == "increment")
            .unwrap();
        increment_meta.actor_role = Some(3);
        let actor_local = PackageRolePoliciesV2::from_metadata(&metadata).unwrap();
        let increment = actor_local
            .methods
            .iter()
            .find(|method| method.method == "increment")
            .unwrap();
        assert!(!increment.public);
        assert_eq!(increment.space_role, None);
        assert_eq!(increment.actor_role, Some(3));
        assert_eq!(
            increment.policy,
            method_role_policy_hash(None, Some(3)).unwrap()
        );
        assert_eq!(
            method_role_policy_hash(None, Some(u8::MAX)),
            None,
            "the metadata no-role sentinel is not a valid actor threshold"
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
            .actor_genesis(actor, "root".into(), None, state.clone())
            .unwrap();
        let policies = PackageRolePoliciesV2::decode(&package.role_policies).unwrap();
        assert_eq!(genesis.actor, actor);
        assert_eq!(genesis.producer, package.deployment_signature.producer);
        assert_eq!(genesis.deployment, package.deployment_id());
        assert_eq!(genesis.program, package.manifest.actor_program);
        assert_eq!(genesis.initial_state, state);
        assert_eq!(
            PackageRolePoliciesV2::decode(&genesis.role_policies).unwrap(),
            policies
        );
        assert_eq!(
            package.actor_genesis(actor, String::new(), None, state.clone()),
            Err(PackageError::InvalidActorName)
        );
        assert_eq!(
            package.actor_genesis(
                actor,
                "x".repeat(super::super::MAX_ACTOR_NAME_BYTES + 1),
                None,
                state,
            ),
            Err(PackageError::InvalidActorName)
        );
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
    fn package_requires_the_protocol_service_program() {
        let mut package = package();
        package.manifest.service_program = ProgramId([9; 32]);
        assert_eq!(
            package.validate(),
            Err(PackageError::ServiceProgramMismatch)
        );
    }
}
