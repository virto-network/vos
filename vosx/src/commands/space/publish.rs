//! `space publish` — add a program to the catalog.

use serde::Serialize;
use vos::registry::Status;
use vos::v2::{V2Wire, VosPackageV2};

use crate::blob_store::{self, BlobHash, BlobSource};
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_ref;
use crate::output;

#[derive(Serialize)]
struct PublishedView {
    name: String,
    version: String,
    hash: String,
}

pub struct Args {
    pub space: String,
    /// `name` or `name:version` matching the signed package manifest.
    pub program_ref: String,
    /// Signed `.vos` blob source: path, hash, ipfs:<cid>, or URL.
    pub source: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (name, version) = parse_program_ref(&args.program_ref)?;

    // Resolve and cache the blob bytes locally.
    let source = BlobSource::parse(&args.source);
    let (source_hash, bytes) =
        blob_store::resolve(&source).map_err(|e| anyhow::anyhow!("blob: {e}"))?;
    let (hash, catalog_bytes, package_meta) =
        canonical_program(&name, &version, source_hash, bytes)?;
    if hash != source_hash {
        blob_store::cache_put(&catalog_bytes)
            .map_err(|e| anyhow::anyhow!("cache canonical program artifact: {e}"))?;
    }

    DaemonClient::with_connect(&args.space, |client| {
        let status = client.publish(name.clone(), version.clone(), hash.0.to_vec())?;
        match status {
            Status::Ok => {
                if let Some(meta) = package_meta.as_deref() {
                    forward_meta_blob(client, &hash, meta);
                }
                emit(&name, &version, &hash);
                Ok(())
            }
            Status::TagConflict => anyhow::bail!(
                "{name}:{version} already exists in the catalog with a different hash; \
                 tags are immutable",
            ),
            other => anyhow::bail!("publish returned status {other}"),
        }
    })
}

pub(crate) fn canonical_program(
    name: &str,
    version: &str,
    source_hash: BlobHash,
    bytes: Vec<u8>,
) -> anyhow::Result<(BlobHash, Vec<u8>, Option<Vec<u8>>)> {
    if bytes.get(..4) != Some(b"VOSP") {
        anyhow::bail!(
            "catalog publishing accepts only signed .vos v2 packages; build the actor with \
             `vosx build --service-pvm <vos-service.pvm>` first"
        );
    }
    let package = VosPackageV2::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("decode .vos v2 package: {error}"))?;
    package.validate()?;
    javm::program::parse_blob(&package.actor_pvm)
        .ok_or_else(|| anyhow::anyhow!("package actor PVM is invalid"))?;
    if package.manifest.name != name || package.manifest.version != version {
        anyhow::bail!(
            "package identity is {}:{}, but publish requested {name}:{version}",
            package.manifest.name,
            package.manifest.version,
        );
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
    // The catalog and CAS retain the exact signed deployment bytes. Root-tree
    // installation must consume this package through the pinned generic
    // service; publishing must not replace package identity with an extracted
    // actor program blob.
    Ok((source_hash, bytes, Some(package.schemas)))
}

fn forward_meta_blob(client: &DaemonClient, hash: &BlobHash, meta_blob: &[u8]) {
    if meta_blob.is_empty() {
        return;
    }
    if let Err(e) = client.register_meta(hash.0.to_vec(), meta_blob.to_vec()) {
        tracing::debug!("register_meta for v2 package skipped: {e}");
    }
}

fn emit(name: &str, version: &str, hash: &BlobHash) {
    if output::is_json() {
        output::print_json(&PublishedView {
            name: name.to_string(),
            version: version.to_string(),
            hash: hash.to_hex(),
        });
    } else {
        println!("published {name}:{version}");
        println!("  hash = {hash}");
    }
}

#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;
    use vos::metadata::{ActorMeta, MessageMeta};
    use vos::v2::{
        DeploymentSignatureV2, Hash, PackageManifestV2, PackageRolePoliciesV2, ProducerId,
        ProgramId, VosPackageV2, artifact_hash,
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
        }],
        constructor: &[],
        kind: 0,
        caps: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
    };

    fn signed_package() -> VosPackageV2 {
        let mut assembler = grey_transpiler::assembler::Assembler::new();
        assembler
            .load_imm_64(grey_transpiler::assembler::Reg::A0, 0)
            .ecalli(0);
        let actor_pvm = assembler.build();
        let (buffer, length) = vos::metadata::encode::<512>(&META);
        let schemas = buffer[..length].to_vec();
        let metadata = vos::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePoliciesV2::from_metadata(&metadata)
            .unwrap()
            .encode();
        let interfaces = Vec::new();
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public().encode_protobuf();
        let mut package = VosPackageV2 {
            manifest: PackageManifestV2 {
                name: "counter".into(),
                version: "2.0.0".into(),
                service_abi: vos::v2::ABI_VERSION,
                snapshot_version: vos::v2::SNAPSHOT_VERSION,
                execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
                service_program: ProgramId([7; 32]),
                actor_program: ProgramId::of_pvm(&actor_pvm),
                crdt: false,
                external_actors: vec![],
                interfaces_hash: artifact_hash(b"interfaces", &interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
            },
            actor_pvm,
            generated_interfaces: interfaces,
            role_policies,
            schemas,
            diagnostics: None,
            deployment_signature: DeploymentSignatureV2 {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![0],
            },
        };
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        package
    }

    #[test]
    fn publishing_v2_retains_the_exact_signed_package() {
        let package = signed_package();
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let (catalog_hash, catalog_bytes, metadata) =
            canonical_program("counter", "2.0.0", source_hash, bytes.clone()).unwrap();

        assert_eq!(catalog_hash, source_hash);
        assert_eq!(catalog_bytes, bytes);
        assert_eq!(metadata, Some(package.schemas));
        assert_ne!(catalog_hash, BlobHash::of(&package.actor_pvm));
    }

    #[test]
    fn publishing_v2_rejects_a_tampered_deployment_signature() {
        let mut package = signed_package();
        package.deployment_signature.signature[0] ^= 0xff;
        let bytes = package.encode();
        let source_hash = BlobHash::of(&bytes);
        let error = canonical_program("counter", "2.0.0", source_hash, bytes).unwrap_err();
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

    #[test]
    fn every_catalog_publish_path_rejects_raw_artifacts() {
        let bytes = b"raw ELF fixture".to_vec();
        let source_hash = BlobHash::of(&bytes);
        assert!(
            canonical_program("counter", "2.0.0", source_hash, bytes,)
                .unwrap_err()
                .to_string()
                .contains("only signed .vos v2 packages")
        );
    }
}
