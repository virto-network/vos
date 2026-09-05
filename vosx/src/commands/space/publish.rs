//! `space publish` — add a program to the catalog.

use serde::Serialize;
use vos::agent::sdk::package::{
    PackageEnvelope as AgentPackage, PackageManifest as AgentPackageManifest, PackageVerifier,
};
use vos::registry::{ProgramKind, Status};
use vos::service::{ServiceWire, VosPackage};

use crate::blob_store::{self, BlobHash, BlobSource};
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{mint_publication_id, parse_program_name};
use crate::output;

#[derive(Serialize)]
struct PublishedView {
    name: String,
    hash: String,
    /// `true` when the name already pointed at this package.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    already_present: bool,
}

pub struct Args {
    pub space: String,
    pub program_ref: String,
    /// Blob source: file path, hash, content identifier, or URL.
    pub source: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let name = parse_program_name(&args.program_ref)?;

    // Resolve and cache the blob bytes locally.
    let source = BlobSource::parse(&args.source);
    let (source_hash, bytes) =
        blob_store::resolve(&source).map_err(|e| anyhow::anyhow!("blob: {e}"))?;
    let program = canonical_program(&name, source_hash, bytes)?;

    DaemonClient::with_connect(&args.space, |client| {
        let current = client.program(&name)?;
        let already_present = match (&program, current.as_ref()) {
            (AdmittedProgram::Service { hash, crdt, .. }, Some(row)) => {
                row.hash == hash.0 && row.kind == (ProgramKind::Service { crdt: *crdt })
            }
            (AdmittedProgram::AgentActor { hash, .. }, Some(row)) => {
                row.hash == hash.0 && row.kind == ProgramKind::AgentActor
            }
            _ => false,
        };
        if already_present {
            let (hash, metadata) = match &program {
                AdmittedProgram::Service { hash, metadata, .. }
                | AdmittedProgram::AgentActor { hash, metadata, .. } => (*hash, metadata),
            };
            // Metadata is a recoverable projection of signed package bytes;
            // retrying an already-present publication may safely heal it.
            forward_meta_blob(client, &hash, metadata);
            emit(&name, &hash, true);
            return Ok(());
        }

        let publication_id = mint_publication_id()?;
        let expected_current = current.as_ref().map(|row| row.tag());
        let (hash, package_meta, status) = match &program {
            AdmittedProgram::Service {
                hash,
                exact_bytes,
                metadata,
                crdt,
            } => (*hash, metadata.as_slice(), {
                debug_assert_eq!(BlobHash::of(exact_bytes), *hash);
                client.publish_service_program(
                    name.clone(),
                    hash.0,
                    *crdt,
                    publication_id,
                    expected_current,
                )?
            }),
            AdmittedProgram::AgentActor {
                hash,
                exact_bytes,
                metadata,
            } => (*hash, metadata.as_slice(), {
                debug_assert_eq!(BlobHash::of(exact_bytes), *hash);
                client.publish_agent_actor_program(
                    name.clone(),
                    hash.0,
                    publication_id,
                    expected_current,
                )?
            }),
        };
        match status {
            Status::Ok => {
                forward_meta_blob(client, &hash, package_meta);
                emit(&name, &hash, false);
                Ok(())
            }
            other => anyhow::bail!("publish returned status {other}"),
        }
    })
}

pub(crate) fn validate_package(name: &str, bytes: &[u8]) -> anyhow::Result<VosPackage> {
    if bytes.get(..4) != Some(b"VOSP") {
        anyhow::bail!("expected a signed .vos service package");
    }
    let package = VosPackage::decode(bytes)
        .map_err(|error| anyhow::anyhow!("decode .vos service package: {error}"))?;
    if package.encode() != bytes {
        anyhow::bail!("signed .vos service package is not canonical");
    }
    package.validate()?;
    vos::service::validate_actor_program_layout(&package.actor_pvm).map_err(|error| {
        anyhow::anyhow!("package actor PVM capability layout is invalid: {error}")
    })?;
    if package.manifest.name != name {
        anyhow::bail!("package is named {}, not {name}", package.manifest.name);
    }
    verify_ed25519_signature(
        "service package",
        &package.deployment_signature.public_key,
        &package.signing_message(),
        &package.deployment_signature.signature,
    )?;
    Ok(package)
}

fn validate_agent_actor_package(name: &str, bytes: &[u8]) -> anyhow::Result<AgentPackage> {
    if bytes.get(..4) != Some(b"VOS3") {
        anyhow::bail!(
            "expected a signed VOS3 AgentActor package; previous Agent package generations are unsupported"
        );
    }
    let package = AgentPackage::decode(bytes)
        .map_err(|error| anyhow::anyhow!("decode VOS3 AgentActor package: {error}"))?;
    let canonical = package
        .encode()
        .map_err(|error| anyhow::anyhow!("encode VOS3 AgentActor package: {error}"))?;
    if canonical != bytes {
        anyhow::bail!("signed VOS3 AgentActor package is not canonical");
    }
    package
        .verify(&RawEd25519PackageVerifier)
        .map_err(|error| anyhow::anyhow!("verify VOS3 AgentActor package: {error}"))?;
    let AgentPackageManifest::Actor(manifest) = &package.manifest else {
        anyhow::bail!("VOS3 AgentRuntime packages cannot be published as AgentActor programs");
    };
    if manifest.name != name {
        anyhow::bail!("package is named {}, not {name}", manifest.name);
    }

    let actor_program = package
        .actor_program_bytes()
        .map_err(|error| anyhow::anyhow!("read VOS3 actor PVM: {error}"))?;
    if vos_pvm::spi::parse_standard_program(actor_program).is_none() {
        anyhow::bail!("VOS3 actor artifact is not a canonical standard PVM");
    }
    let task_set = package
        .task_dependency_set()
        .map_err(|error| anyhow::anyhow!("read VOS3 Task dependency set: {error}"))?;
    for dependency in task_set.dependencies {
        let program = package
            .task_program_bytes(dependency.task)
            .map_err(|error| anyhow::anyhow!("read VOS3 Task PVM: {error}"))?;
        if vos_pvm::spi::parse_standard_program(program).is_none() {
            anyhow::bail!("VOS3 Task artifact is not a canonical standard PVM");
        }
    }
    Ok(package)
}

struct RawEd25519PackageVerifier;

impl PackageVerifier for RawEd25519PackageVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = libp2p::identity::ed25519::PublicKey::try_from_bytes(public_key) else {
            return false;
        };
        key.verify(message, signature)
    }
}

fn verify_ed25519_signature(
    label: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    let decoded = libp2p::identity::PublicKey::try_decode_protobuf(public_key)
        .map_err(|error| anyhow::anyhow!("decode {label} producer public key: {error}"))?;
    if decoded.encode_protobuf() != public_key {
        anyhow::bail!("{label} producer public key is not canonically encoded");
    }
    let ed25519 = decoded
        .try_into_ed25519()
        .map_err(|_| anyhow::anyhow!("{label} producer public key is not Ed25519"))?;
    if !ed25519.verify(message, signature) {
        anyhow::bail!("{label} deployment signature is invalid");
    }
    Ok(())
}

/// A completely validated package and the one catalog verb it may drive.
/// Keeping CRDT capability inside only the service variant makes it
/// impossible for the caller to infer an execution class from a loose flag.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdmittedProgram {
    Service {
        hash: BlobHash,
        /// Exact signed VOSP envelope retained by the CAS and catalog.
        exact_bytes: Vec<u8>,
        metadata: Vec<u8>,
        crdt: bool,
    },
    AgentActor {
        hash: BlobHash,
        /// Exact signed VOS3 envelope retained by the CAS and catalog.
        exact_bytes: Vec<u8>,
        /// Exact AAI1 introspection artifact authenticated by the package.
        metadata: Vec<u8>,
    },
}

pub(crate) fn canonical_program(
    name: &str,
    source_hash: BlobHash,
    bytes: Vec<u8>,
) -> anyhow::Result<AdmittedProgram> {
    if BlobHash::of(&bytes) != source_hash {
        anyhow::bail!("resolved package bytes do not match their content hash");
    }
    match bytes.get(..4) {
        Some(b"VOSP") => {
            let package = validate_package(name, &bytes)?;
            // Root-tree installation consumes the complete signed service
            // package; publication never substitutes its extracted actor PVM.
            Ok(AdmittedProgram::Service {
                hash: source_hash,
                exact_bytes: bytes,
                metadata: package.schemas,
                crdt: package.manifest.crdt,
            })
        }
        Some(b"VOS3") => {
            let package = validate_agent_actor_package(name, &bytes)?;
            let AgentPackageManifest::Actor(manifest) = &package.manifest else {
                unreachable!("AgentRuntime package rejected during validation")
            };
            let metadata = package
                .artifacts
                .iter()
                .find(|artifact| artifact.identity == manifest.introspection)
                .map(|artifact| artifact.bytes.clone())
                .ok_or_else(|| anyhow::anyhow!("VOS3 package omitted its AAI1 introspection"))?;
            // The Agent Host consumes the exact VOS3 envelope. Public
            // introspection is an authenticated closure member, never a
            // caller-selected metadata side channel.
            Ok(AdmittedProgram::AgentActor {
                hash: source_hash,
                exact_bytes: bytes,
                metadata,
            })
        }
        _ => anyhow::bail!(
            "expected a signed VOSP service or VOS3 AgentActor package; previous Agent package generations are unsupported"
        ),
    }
}

fn forward_meta_blob(client: &DaemonClient, hash: &BlobHash, meta_blob: &[u8]) {
    if meta_blob.is_empty() {
        return;
    }
    if let Err(e) = client.register_meta(hash.0.to_vec(), meta_blob.to_vec()) {
        tracing::debug!("register_meta for signed package skipped: {e}");
    }
}

fn emit(name: &str, hash: &BlobHash, already_present: bool) {
    if output::is_json() {
        output::print_json(&PublishedView {
            name: name.to_string(),
            hash: hash.to_hex(),
            already_present,
        });
    } else if already_present {
        println!("{name} already points to this package");
        println!("  hash = {hash}");
    } else {
        println!("published {name}");
        println!("  hash = {hash}");
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use libp2p::identity::Keypair;
    use vos::agent::sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos::agent::sdk::introspection::ActorIntrospectionArtifact;
    use vos::agent::sdk::method_policy::ActorMethodPolicyArtifact;
    use vos::agent::sdk::package::{
        ActorPackageManifest, AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope,
        PackageManifest as CleanPackageManifest, PackageSigning,
    };
    use vos::agent::sdk::schema::{ConstructorContract, ParsedSchema};
    use vos::agent::sdk::task::{TaskDependency, TaskDependencySetArtifact, TaskProofRequirement};
    use vos::agent::sdk::wire::CanonicalWire as _;
    use vos::agent::sdk::{
        BlobRef as AgentBlobRef, LaneSet, ProducerId as AgentProducerId,
        ProgramId as AgentProgramId, ProofSystemSet, RuntimeCapabilities, RuntimeRequirements,
    };
    use vos::metadata::{ActorMeta, MessageMeta};
    use vos::service::{
        DeploymentSignature, Hash, PackageManifest, PackageRolePolicies, ProducerId, ProgramId,
        VosPackage, artifact_hash,
    };

    use super::*;

    const META: ActorMeta = ActorMeta {
        actor_name: "counter",
        messages: &[MessageMeta {
            name: "value",
            is_query: true,
            fields: &[],
            returns: "u64",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            capability: None,
            space_role: None,
            actor_role: None,
        }],
        constructor: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    fn actor_pvm() -> Vec<u8> {
        let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
        assembler
            .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 0)
            .ecalli(0);
        assembler.build()
    }

    fn standard_pvm() -> Vec<u8> {
        let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
        assembler.trap();
        assembler.build_standard()
    }

    fn signed_package() -> VosPackage {
        let actor_pvm = actor_pvm();
        let (buffer, length) = vos::metadata::encode::<512>(&META);
        let schemas = buffer[..length].to_vec();
        let metadata = vos::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&metadata)
            .unwrap()
            .encode();
        let interfaces = Vec::new();
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public().encode_protobuf();
        let mut package = VosPackage {
            manifest: PackageManifest {
                name: "counter".into(),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
                service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
                actor_program: ProgramId::of_pvm(&actor_pvm),
                crdt: false,
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                task_dependencies_hash: vos::service::task_dependencies_hash(&[]),
            },
            actor_pvm,
            generated_interfaces: interfaces,
            role_policies,
            schemas,
            task_dependencies: vec![],
            diagnostics: None,
            deployment_signature: DeploymentSignature {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![0],
            },
        };
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        package
    }

    fn clean_artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: AgentBlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn sign_clean(mut package: PackageEnvelope) -> PackageEnvelope {
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let message = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = key.sign(&message).to_bytes();
        package
    }

    fn replace_clean_artifact(
        package: &mut PackageEnvelope,
        previous: AgentBlobRef,
        replacement: &[u8],
    ) -> AgentBlobRef {
        let artifact = package
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.identity == previous)
            .unwrap();
        *artifact = clean_artifact(replacement);
        package
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        AgentBlobRef::of_bytes(replacement)
    }

    fn signed_agent_actor_package() -> PackageEnvelope {
        let program = standard_pvm();
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: Vec::new(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: AgentBlobRef::of_bytes(&schema),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let introspection = ActorIntrospectionArtifact {
            actor_schema: AgentBlobRef::of_bytes(&schema),
            method_policy: AgentBlobRef::of_bytes(&policy),
            actor_doc: "A counter actor.".into(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let tasks = TaskDependencySetArtifact {
            dependencies: Vec::new(),
        }
        .encode()
        .unwrap();
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key = key.verifying_key().to_bytes();
        let signing = PackageSigning {
            producer: AgentProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; 64],
        };
        let mut artifacts = [&program[..], &schema, &policy, &introspection, &tasks]
            .into_iter()
            .map(clean_artifact)
            .collect::<Vec<_>>();
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        sign_clean(PackageEnvelope {
            manifest: CleanPackageManifest::Actor(ActorPackageManifest {
                name: "counter".into(),
                program: AgentBlobRef::of_bytes(&program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: AgentBlobRef::of_bytes(&schema),
                method_policy: AgentBlobRef::of_bytes(&policy),
                introspection: AgentBlobRef::of_bytes(&introspection),
                task_dependencies: AgentBlobRef::of_bytes(&tasks),
                scheduling: false,
                requirements: RuntimeRequirements {
                    lanes: LaneSet::NONE,
                    scheduling: false,
                    proof_systems: ProofSystemSet::EMPTY,
                },
                signing,
            }),
            artifacts,
        })
    }

    fn signed_agent_runtime_package() -> PackageEnvelope {
        let pvm = standard_pvm();
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key = key.verifying_key().to_bytes();
        sign_clean(PackageEnvelope {
            manifest: CleanPackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "standard-runtime".into(),
                outer_program: AgentBlobRef::of_bytes(&pvm),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: PackageSigning {
                    producer: AgentProducerId::of_public_key(&public_key),
                    public_key,
                    signature: [0; 64],
                },
            }),
            artifacts: vec![clean_artifact(&pvm)],
        })
    }

    fn signed_agent_actor_with_invalid_task_pvm() -> PackageEnvelope {
        let mut package = signed_agent_actor_package();
        let invalid_task = b"not a standard task pvm";
        let dependency = TaskDependency::new(
            AgentBlobRef::of_bytes(invalid_task),
            AgentProgramId::of_pvm(invalid_task),
            64,
            128,
            TaskProofRequirement::None,
        )
        .unwrap();
        let tasks = TaskDependencySetArtifact {
            dependencies: vec![dependency],
        }
        .encode()
        .unwrap();
        let CleanPackageManifest::Actor(manifest) = &mut package.manifest else {
            unreachable!()
        };
        let previous = manifest.task_dependencies.clone();
        manifest.task_dependencies = AgentBlobRef::of_bytes(&tasks);
        replace_clean_artifact(&mut package, previous, &tasks);
        package.artifacts.push(clean_artifact(invalid_task));
        package
            .artifacts
            .sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        sign_clean(package)
    }

    #[test]
    fn publishing_service_retains_the_exact_signed_package() {
        let package = signed_package();
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let admitted = canonical_program("counter", source_hash, bytes.clone()).unwrap();

        let AdmittedProgram::Service {
            hash,
            exact_bytes,
            metadata,
            crdt,
        } = admitted
        else {
            panic!("VOSP package admitted with the wrong catalog kind")
        };
        assert_eq!(hash, source_hash);
        assert_eq!(exact_bytes, bytes);
        assert_eq!(metadata, package.schemas);
        assert!(!crdt);
        assert_ne!(hash, BlobHash::of(&package.actor_pvm));
    }

    #[test]
    fn publishing_agent_actor_retains_the_exact_signed_vos3_package() {
        let package = signed_agent_actor_package();
        let bytes = package.encode().unwrap();
        let source_hash = BlobHash::of(&bytes);
        let admitted = canonical_program("counter", source_hash, bytes.clone()).unwrap();

        let AdmittedProgram::AgentActor {
            hash,
            exact_bytes,
            metadata,
        } = admitted
        else {
            panic!("VOS3 actor package admitted with the wrong catalog kind")
        };
        let CleanPackageManifest::Actor(manifest) = &package.manifest else {
            unreachable!()
        };
        let expected_introspection = package
            .artifacts
            .iter()
            .find(|artifact| artifact.identity == manifest.introspection)
            .unwrap();
        assert_eq!(hash, source_hash);
        assert_eq!(exact_bytes, bytes);
        assert_eq!(metadata, expected_introspection.bytes);
        assert_ne!(hash, BlobHash::of(package.actor_program_bytes().unwrap()));
    }

    #[test]
    fn publishing_rejects_tampered_service_and_agent_signatures() {
        let mut service = signed_package().encode();
        *service.last_mut().unwrap() ^= 0xff;
        let mut agent = signed_agent_actor_package();
        agent.manifest.signing_mut().signature[0] ^= 0xff;
        let agent = agent.encode().unwrap();

        let service_error =
            canonical_program("counter", BlobHash::of(&service), service).unwrap_err();
        assert!(
            service_error
                .to_string()
                .contains("deployment signature is invalid")
        );
        let agent_error = canonical_program("counter", BlobHash::of(&agent), agent).unwrap_err();
        assert!(
            agent_error
                .to_string()
                .contains("invalid package signature")
        );
    }

    #[test]
    fn publishing_rejects_trailing_bytes_for_both_package_wires() {
        for mut bytes in [
            signed_package().encode(),
            signed_agent_actor_package().encode().unwrap(),
        ] {
            bytes.push(0);
            let error = canonical_program("counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(error.to_string().contains("TrailingBytes"));
        }
    }

    #[test]
    fn publishing_rejects_noncanonical_boolean_encodings() {
        let mut service = signed_package().encode();
        let service_crdt = 36 + 4 + "counter".len() + 4 * 32;
        assert_eq!(service[service_crdt], 0);
        service[service_crdt] = 2;

        let mut agent = signed_agent_actor_package().encode().unwrap();
        let agent_scheduling = 4 + 2 + 32 + 1 + 4 + "counter".len() + 40 + 4 + 4 * 40;
        assert_eq!(agent[agent_scheduling], 0);
        agent[agent_scheduling] = 2;

        for bytes in [service, agent] {
            let error = canonical_program("counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(error.to_string().contains("NonCanonical"));
        }
    }

    #[test]
    fn publishing_rejects_noncanonical_service_and_mismatched_agent_producer_keys() {
        let mut service = signed_package();
        service
            .deployment_signature
            .public_key
            .extend_from_slice(&[0x18, 0x00]);
        service.deployment_signature.producer =
            ProducerId::of_public_key(&service.deployment_signature.public_key);

        let service = service.encode();
        let error = canonical_program("counter", BlobHash::of(&service), service).unwrap_err();
        assert!(error.to_string().contains("not canonically encoded"));

        let mut agent = signed_agent_actor_package().encode().unwrap();
        let public_key_offset =
            4 + 2 + 32 + 1 + 4 + "counter".len() + 40 + 4 + 4 * 40 + 1 + 1 + 1 + 1 + 32;
        agent[public_key_offset] ^= 0x01;
        let error = canonical_program("counter", BlobHash::of(&agent), agent).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("producer does not match public key")
        );
    }

    #[test]
    fn publishing_requires_the_exact_signed_manifest_name() {
        for bytes in [
            signed_package().encode(),
            signed_agent_actor_package().encode().unwrap(),
        ] {
            let error = canonical_program("not-counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("package is named counter, not not-counter")
            );
        }
    }

    #[test]
    fn publishing_rejects_vos3_agent_runtime_packages() {
        let bytes = signed_agent_runtime_package().encode().unwrap();
        let error = canonical_program("standard-runtime", BlobHash::of(&bytes), bytes).unwrap_err();
        assert!(error.to_string().contains("AgentRuntime"));
    }

    #[test]
    fn publishing_rejects_nonstandard_actor_and_task_programs() {
        let mut actor = signed_agent_actor_package();
        let invalid_actor = b"not a standard actor pvm";
        let CleanPackageManifest::Actor(manifest) = &mut actor.manifest else {
            unreachable!()
        };
        let previous = manifest.program.clone();
        manifest.program = AgentBlobRef::of_bytes(invalid_actor);
        replace_clean_artifact(&mut actor, previous, invalid_actor);
        let actor = sign_clean(actor).encode().unwrap();
        let error = canonical_program("counter", BlobHash::of(&actor), actor).unwrap_err();
        assert!(error.to_string().contains("actor artifact"));

        let task = signed_agent_actor_with_invalid_task_pvm().encode().unwrap();
        let error = canonical_program("counter", BlobHash::of(&task), task).unwrap_err();
        assert!(error.to_string().contains("Task artifact"));
    }

    #[test]
    fn package_magics_cannot_be_relabelled_across_catalog_kinds() {
        let service = signed_package().encode();
        assert!(
            validate_agent_actor_package("counter", &service)
                .unwrap_err()
                .to_string()
                .contains("expected a signed VOS3")
        );
        let agent = signed_agent_actor_package().encode().unwrap();
        assert!(
            validate_package("counter", &agent)
                .unwrap_err()
                .to_string()
                .contains("expected a signed .vos service package")
        );

        let mut service_as_agent = signed_package().encode();
        service_as_agent[..4].copy_from_slice(b"VOS3");
        let error = canonical_program("counter", BlobHash::of(&service_as_agent), service_as_agent)
            .unwrap_err();
        assert!(error.to_string().contains("VOS3"));

        let mut agent_as_service = signed_agent_actor_package().encode().unwrap();
        agent_as_service[..4].copy_from_slice(b"VOSP");
        let error = canonical_program("counter", BlobHash::of(&agent_as_service), agent_as_service)
            .unwrap_err();
        assert!(error.to_string().contains("service package"));

        let legacy = b"VOSK obsolete-agent-envelope".to_vec();
        let error = canonical_program("counter", BlobHash::of(&legacy), legacy).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("previous Agent package generations")
        );
    }

    #[test]
    fn package_identity_is_not_the_catalog_content_hash() {
        let package = signed_package();
        assert_ne!(
            Hash(package.deployment_id().0),
            Hash(BlobHash::of(&package.encode()).0)
        );
    }
}
