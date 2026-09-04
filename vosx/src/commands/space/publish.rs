//! `space publish` — add a program to the catalog.

use serde::Serialize;
use vos::agent::PackageKind;
use vos::agent::package::Package as AgentPackage;
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
    if bytes.get(..4) != Some(b"VOSK") {
        anyhow::bail!("expected a signed VOSK agent package");
    }
    let package = AgentPackage::decode(bytes)
        .map_err(|error| anyhow::anyhow!("decode VOSK agent package: {error}"))?;
    if package.encode() != bytes {
        anyhow::bail!("signed VOSK agent package is not canonical");
    }
    package
        .validate()
        .map_err(|error| anyhow::anyhow!("validate VOSK agent package: {error}"))?;
    if package.manifest.name != name {
        anyhow::bail!("package is named {}, not {name}", package.manifest.name);
    }
    verify_ed25519_signature(
        "VOSK agent package",
        &package.deployment_signature.public_key,
        &package.signing_message(),
        &package.deployment_signature.signature,
    )?;
    if !matches!(package.manifest.kind, PackageKind::Actor { .. }) {
        anyhow::bail!("VOSK AgentRuntime packages cannot be published as AgentActor programs");
    }
    Ok(package)
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
        /// Exact signed VOSK envelope retained by the CAS and catalog.
        exact_bytes: Vec<u8>,
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
        Some(b"VOSK") => {
            let package = validate_agent_actor_package(name, &bytes)?;
            // The Local Agent Host likewise consumes the exact VOSK envelope.
            // Public metadata remains the `.vos_meta` artifact authenticated
            // by that package, not a caller-selected side channel.
            Ok(AdmittedProgram::AgentActor {
                hash: source_hash,
                exact_bytes: bytes,
                metadata: package.schemas,
            })
        }
        _ => anyhow::bail!("expected a signed VOSP service or VOSK AgentActor package"),
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
    use libp2p::identity::Keypair;
    use vos::agent::contract::{ActorPackageContract, RuntimePackageContract};
    use vos::agent::package::{
        Package as AgentPackage, PackageManifest as AgentPackageManifest,
        actor_runtime_requirements,
    };
    use vos::agent::schema::{
        ExecutionEntryKind, MethodMeta as AgentMethodMeta, SchemaMeta as AgentSchemaMeta,
    };
    use vos::agent::{MethodMode, PackageKind, RuntimeCapabilities};
    use vos::metadata::{ActorMeta, MessageMeta};
    use vos::service::{
        DeploymentSignature, Hash, PackageManifest, PackageRolePolicies, ProducerId, ProgramId,
        VosPackage, artifact_hash, task_dependencies_hash,
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

    const AGENT_SCHEMA: AgentSchemaMeta = AgentSchemaMeta {
        uses_storage: false,
        fields: &[],
        methods: &[AgentMethodMeta {
            name: "value",
            mode: MethodMode::Query,
            explicit: true,
        }],
    };

    fn actor_pvm() -> Vec<u8> {
        let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
        assembler
            .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 0)
            .ecalli(0);
        assembler.build()
    }

    fn agent_pvm() -> Vec<u8> {
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

    fn signed_agent_actor_package() -> AgentPackage {
        let pvm = agent_pvm();
        let (metadata_buffer, metadata_len) = vos::metadata::encode::<512>(&META);
        let schemas = metadata_buffer[..metadata_len].to_vec();
        let metadata = vos::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&metadata)
            .unwrap()
            .encode();
        let (agent_buffer, agent_len) = vos::agent::schema::encode_with_entry::<512>(
            &AGENT_SCHEMA,
            ExecutionEntryKind::AgentActor,
        );
        let agent_schema = agent_buffer[..agent_len].to_vec();
        let parsed_agent_schema = vos::agent::schema::decode(&agent_schema).unwrap();
        let generated_interfaces = Vec::new();
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public().encode_protobuf();
        let mut package = AgentPackage {
            manifest: AgentPackageManifest {
                name: "counter".into(),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::agent::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::Actor {
                    contract: ActorPackageContract::canonical(),
                    requirements: actor_runtime_requirements(
                        &parsed_agent_schema,
                        &metadata,
                        false,
                    ),
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
            deployment_signature: DeploymentSignature {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![0],
            },
        };
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        package.validate().unwrap();
        package
    }

    fn signed_agent_runtime_package() -> AgentPackage {
        let pvm = agent_pvm();
        let generated_interfaces = b"agent-runtime-lifecycle".to_vec();
        let schemas = b"agent-runtime-schema".to_vec();
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public().encode_protobuf();
        let mut package = AgentPackage {
            manifest: AgentPackageManifest {
                name: "standard-runtime".into(),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::agent::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: DeploymentSignature {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![0],
            },
        };
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        package.validate().unwrap();
        package
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
    fn publishing_agent_actor_retains_the_exact_signed_vosk_package() {
        let package = signed_agent_actor_package();
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let admitted = canonical_program("counter", source_hash, bytes.clone()).unwrap();

        let AdmittedProgram::AgentActor {
            hash,
            exact_bytes,
            metadata,
        } = admitted
        else {
            panic!("VOSK actor package admitted with the wrong catalog kind")
        };
        assert_eq!(hash, source_hash);
        assert_eq!(exact_bytes, bytes);
        assert_eq!(metadata, package.schemas);
        assert_ne!(hash, BlobHash::of(&package.pvm));
    }

    #[test]
    fn publishing_rejects_tampered_service_and_agent_signatures() {
        let mut service = signed_package().encode();
        *service.last_mut().unwrap() ^= 0xff;
        let mut agent = signed_agent_actor_package().encode();
        *agent.last_mut().unwrap() ^= 0xff;

        for bytes in [service, agent] {
            let error = canonical_program("counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("deployment signature is invalid")
            );
        }
    }

    #[test]
    fn publishing_rejects_trailing_bytes_for_both_package_wires() {
        for mut bytes in [
            signed_package().encode(),
            signed_agent_actor_package().encode(),
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

        let mut agent = signed_agent_actor_package().encode();
        let agent_scheduling = 36 + 4 + "counter".len() + 2 * 32 + 1 + 4 + 1;
        assert_eq!(agent[agent_scheduling], 0);
        agent[agent_scheduling] = 2;

        for bytes in [service, agent] {
            let error = canonical_program("counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(error.to_string().contains("NonCanonical"));
        }
    }

    #[test]
    fn publishing_rejects_noncanonical_producer_key_encodings() {
        let mut service = signed_package();
        service
            .deployment_signature
            .public_key
            .extend_from_slice(&[0x18, 0x00]);
        service.deployment_signature.producer =
            ProducerId::of_public_key(&service.deployment_signature.public_key);

        let mut agent = signed_agent_actor_package();
        agent
            .deployment_signature
            .public_key
            .extend_from_slice(&[0x18, 0x00]);
        agent.deployment_signature.producer =
            ProducerId::of_public_key(&agent.deployment_signature.public_key);

        for bytes in [service.encode(), agent.encode()] {
            let error = canonical_program("counter", BlobHash::of(&bytes), bytes).unwrap_err();
            assert!(error.to_string().contains("not canonically encoded"));
        }
    }

    #[test]
    fn publishing_requires_the_exact_signed_manifest_name() {
        for bytes in [
            signed_package().encode(),
            signed_agent_actor_package().encode(),
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
    fn publishing_rejects_vosk_agent_runtime_packages() {
        let bytes = signed_agent_runtime_package().encode();
        let error = canonical_program("standard-runtime", BlobHash::of(&bytes), bytes).unwrap_err();
        assert!(error.to_string().contains("AgentRuntime"));
    }

    #[test]
    fn package_magics_cannot_be_relabelled_across_catalog_kinds() {
        let service = signed_package().encode();
        assert!(
            validate_agent_actor_package("counter", &service)
                .unwrap_err()
                .to_string()
                .contains("expected a signed VOSK")
        );
        let agent = signed_agent_actor_package().encode();
        assert!(
            validate_package("counter", &agent)
                .unwrap_err()
                .to_string()
                .contains("expected a signed .vos service package")
        );

        let mut service_as_agent = signed_package().encode();
        service_as_agent[..4].copy_from_slice(b"VOSK");
        let error = canonical_program("counter", BlobHash::of(&service_as_agent), service_as_agent)
            .unwrap_err();
        assert!(error.to_string().contains("VOSK"));

        let mut agent_as_service = signed_agent_actor_package().encode();
        agent_as_service[..4].copy_from_slice(b"VOSP");
        let error = canonical_program("counter", BlobHash::of(&agent_as_service), agent_as_service)
            .unwrap_err();
        assert!(error.to_string().contains("service package"));
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
