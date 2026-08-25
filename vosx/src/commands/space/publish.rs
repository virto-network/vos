//! `space publish` — add a program to the catalog.

use serde::Serialize;
use vos::registry::Status;
use vos::service::{ServiceWire, VosPackage};

use crate::blob_store::{self, BlobHash, BlobSource};
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_name;
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
    let (hash, catalog_bytes, package_meta, crdt) = canonical_program(&name, source_hash, bytes)?;
    if hash != source_hash {
        blob_store::cache_put(&catalog_bytes)
            .map_err(|e| anyhow::anyhow!("cache canonical program artifact: {e}"))?;
    }

    DaemonClient::with_connect(&args.space, |client| {
        let status = client.publish(name.clone(), hash.0.to_vec(), crdt)?;
        match status {
            Status::Ok => {
                if let Some(meta) = package_meta.as_deref() {
                    forward_meta_blob(client, &hash, meta);
                }
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
    package.validate()?;
    vos::service::validate_actor_program_layout(&package.actor_pvm).map_err(|error| {
        anyhow::anyhow!("package actor PVM capability layout is invalid: {error}")
    })?;
    if package.manifest.name != name {
        anyhow::bail!("package is named {}, not {name}", package.manifest.name);
    }
    let public_key =
        libp2p::identity::PublicKey::try_decode_protobuf(&package.deployment_signature.public_key)
            .map_err(|error| anyhow::anyhow!("decode deployment public key: {error}"))?;
    if !public_key.verify(
        &package.signing_message(),
        &package.deployment_signature.signature,
    ) {
        anyhow::bail!("deployment signature is invalid");
    }
    Ok(package)
}

fn canonical_program(
    name: &str,
    source_hash: BlobHash,
    bytes: Vec<u8>,
) -> anyhow::Result<(BlobHash, Vec<u8>, Option<Vec<u8>>, bool)> {
    let package = validate_package(name, &bytes)?;
    // The catalog and CAS retain the exact signed deployment bytes. Root-tree
    // installation must consume this package through the pinned generic
    // service; publishing must not replace package identity with an extracted
    // actor program blob.
    Ok((
        source_hash,
        bytes,
        Some(package.schemas),
        package.manifest.crdt,
    ))
}

fn forward_meta_blob(client: &DaemonClient, hash: &BlobHash, meta_blob: &[u8]) {
    if meta_blob.is_empty() {
        return;
    }
    if let Err(e) = client.register_meta(hash.0.to_vec(), meta_blob.to_vec()) {
        tracing::debug!("register_meta for service package skipped: {e}");
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
            space_role: None,
            actor_role: None,
        }],
        constructor: &[],
        kind: 0,
        caps: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    fn signed_package() -> VosPackage {
        let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
        assembler
            .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 0)
            .ecalli(0);
        let actor_pvm = assembler.build();
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

    #[test]
    fn publishing_service_retains_the_exact_signed_package() {
        let package = signed_package();
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let (catalog_hash, catalog_bytes, metadata, crdt) =
            canonical_program("counter", source_hash, bytes.clone()).unwrap();

        assert_eq!(catalog_hash, source_hash);
        assert_eq!(catalog_bytes, bytes);
        assert_eq!(metadata, Some(package.schemas));
        assert!(!crdt);
        assert_ne!(catalog_hash, BlobHash::of(&package.actor_pvm));
    }

    #[test]
    fn publishing_service_rejects_a_tampered_deployment_signature() {
        let mut package = signed_package();
        package.deployment_signature.signature[0] ^= 0xff;
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let error = canonical_program("counter", source_hash, bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("deployment signature is invalid")
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
