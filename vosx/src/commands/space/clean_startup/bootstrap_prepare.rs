//! Offline deployment preparation using the existing NEN1 and CBI1 formats.
//! No network, live Agent admission, or startup-policy override is performed.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use libp2p::identity::{KeyType, Keypair};
use redb::ReadableTable as _;
use vos::agent::clean_bootstrap::MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES;
use vos::agent::host::LocalMergeAuthenticator as _;
use vos::agent::private_crypto::StrictNodeEncryptionEnrollmentVerifier;
use vos::agent::sdk::private::NodeEncryptionEnrollment;
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{PrincipalId, SpaceId};

use super::{
    CleanSystemAgentGenesisArchive, Ed25519NodeMergeAuthenticator, HostAgentId, HostHash,
    HostNodeId, HostSpaceId, SYSTEM_AUTHORITY_NAME, SYSTEM_CATALOG_NAME, SystemAgentTrust,
    SystemBootstrapMaterials, derive_node_encryption_public, host_authority_binding,
    node_id_from_authenticated_peer, raw_public_key, sign_node_encryption_enrollment,
    system_logical_slot,
};
use crate::commands::space::clean_store::CleanSystemAgentFileStores;

const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");
// Deployment preparation is bounded and offline, not an unbounded history
// audit of a running registry. A fresh deployment is well below these limits.
const MAX_GENESIS_ROWS: usize = 8_192;
const MAX_GENESIS_SCAN_BYTES: usize = 8 * 1024 * 1024;

#[derive(clap::Args, Debug)]
pub struct ExportBootstrapEnrollmentArgs {
    /// Known local Space ID or name. Its immutable registry root is verified.
    pub space: String,
    /// Fresh output file under an existing canonical, private directory.
    pub output: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrepareCommonBootstrapArgs {
    /// Known local Space ID or name; this node must be one of the three voters.
    pub space: String,
    /// Fresh private directory; common.bundle and certification/ are retained.
    pub output: PathBuf,
    /// Canonical NEN1 file exported independently by each actual node. Repeat three times.
    #[arg(long = "enrollment", required = true, action = clap::ArgAction::Append)]
    pub enrollments: Vec<PathBuf>,
}

pub(crate) fn export_bootstrap_enrollment(
    args: ExportBootstrapEnrollmentArgs,
) -> anyhow::Result<()> {
    let (data, space) = resolve_space(&args.space)?;
    let _space_lock = crate::commands::space::space_lock::SpaceDataLock::exclusive(&space.0)?;
    let root_public = read_space_root(&data, space)?;
    let daemon = read_node_key(&data)?;
    let enrollment = local_enrollment(space, root_public, &daemon)?;
    let bytes = enrollment.encode()?;
    write_fresh_file(
        &args.output,
        &bytes,
        NodeEncryptionEnrollment::MAX_ENCODED_BYTES,
    )?;
    println!(
        "Node {} enrollment written to {} (public possession proof; not live admission)",
        hex::encode(enrollment.node.0),
        args.output.display(),
    );
    Ok(())
}

pub(crate) fn prepare_common_bootstrap(args: PrepareCommonBootstrapArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.enrollments.len() == 3,
        "exactly three enrollment files are required"
    );
    let (data, space) = resolve_space(&args.space)?;
    let _space_lock = crate::commands::space::space_lock::SpaceDataLock::exclusive(&space.0)?;
    let root_public = read_space_root(&data, space)?;
    let operator = crate::identity::load_existing()?;
    anyhow::ensure!(
        raw_public_key(&operator)? == root_public,
        "existing operator identity is not this Space's immutable root",
    );
    let daemon = read_node_key(&data)?;
    let enrollments: Vec<_> = args
        .enrollments
        .iter()
        .map(|path| read_enrollment(path))
        .collect::<Result<_, _>>()?;
    validate_enrollments(space, root_public, &daemon, &enrollments)?;
    let runtime = crate::bundled::root_signed_system_agent_runtime_package(&operator)?;
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        SYSTEM_AUTHORITY_NAME,
        &operator,
    )?;
    let catalog = crate::bundled::root_signed_actor_package(
        crate::bundled::system_catalog_package_template(),
        SYSTEM_CATALOG_NAME,
        &operator,
    )?;
    let materials = SystemBootstrapMaterials::new(
        space,
        root_public,
        node_id_from_authenticated_peer(&daemon.public().to_peer_id()),
        runtime,
        authority,
        catalog,
        &enrollments,
    )?;
    prepare_materials(materials, &operator, &daemon, &args.output).with_context(|| {
        format!("common-bootstrap preparation failed; any real certification data remains in {} and is not automatically removed", args.output.display())
    })?;
    println!(
        "Prepared {}/common.bundle for three voters. Retain certification/; startup remains subject to release qualification and its existing gate.",
        args.output.display(),
    );
    Ok(())
}

fn resolve_space(query: &str) -> anyhow::Result<(PathBuf, SpaceId)> {
    let index = crate::spaces_index::load()?;
    let entry = crate::spaces_index::find(&index, query)?;
    let space = SpaceId(
        entry
            .id_bytes()
            .ok_or_else(|| anyhow::anyhow!("invalid indexed Space ID"))?,
    );
    anyhow::ensure!(
        space != SpaceId::ZERO && entry.pending_recipe.is_empty(),
        "Space is not a clean initialized deployment"
    );
    let data = PathBuf::from(&entry.data_dir);
    anyhow::ensure!(
        data.is_absolute() && data.canonicalize()? == data,
        "Space data directory must be canonical"
    );
    let metadata = fs::symlink_metadata(&data)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "Space data directory must be owner-only"
    );
    Ok((data, space))
}

fn read_space_root(data: &Path, space: SpaceId) -> anyhow::Result<[u8; 32]> {
    read_space_root_with_audit_parent(data, space, &crate::paths::cache_root())
}

fn read_space_root_with_audit_parent(
    data: &Path,
    space: SpaceId,
    audit_parent: &Path,
) -> anyhow::Result<[u8; 32]> {
    let path = data.join("agents").join(format!(
        "{:08x}.redb",
        vos::abi::service::ServiceId::REGISTRY.0
    ));
    let named = fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        named.is_file()
            && !named.file_type().is_symlink()
            && named.nlink() == 1
            && named.uid() == unsafe { libc::geteuid() },
        "registry must be an existing owned, unaliased regular file"
    );
    anyhow::ensure!(
        path.canonicalize()? == path,
        "registry path must not contain aliases"
    );
    // The Space lease excludes a live daemon. redb still rewrites metadata
    // during open/drop, so all database activity stays in a bounded private
    // disk copy; neither success nor refusal can repair the actual registry.
    crate::commands::space::backup::with_registry_audit_copy(&path, audit_parent, None, |db| {
        let transaction = db.begin_read()?;
        let table = transaction.open_table(DAG_TABLE)?;
        let mut scanned_bytes = 0usize;
        let mut root = None;
        for (index, row) in table.iter()?.enumerate() {
            anyhow::ensure!(
                index < MAX_GENESIS_ROWS,
                "registry genesis scan exceeds its row bound"
            );
            let (key, value) = row?;
            scanned_bytes = scanned_bytes
                .checked_add(value.value().len())
                .ok_or_else(|| anyhow::anyhow!("registry genesis size overflow"))?;
            anyhow::ensure!(
                scanned_bytes <= MAX_GENESIS_SCAN_BYTES,
                "registry genesis scan exceeds its byte bound"
            );
            let Some(cid) =
                crate::commands::space::common::registry_genesis_cid(key.value(), value.value())
            else {
                continue;
            };
            if crate::commands::space::common::derive_space_id(&cid) != space.0 {
                continue;
            }
            anyhow::ensure!(
                root.is_none(),
                "registry has multiple Space signing-root anchors"
            );
            let request = vos::node::registry_replay_node_request(value.value())
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| anyhow::anyhow!("missing registry genesis request"))?;
            let peer = request
                .args
                .get_bytes("root")
                .ok_or_else(|| anyhow::anyhow!("missing registry signing root"))?;
            root = Some(
                vos::registry::ed25519_pubkey_from_peer_id(&peer).ok_or_else(|| {
                    anyhow::anyhow!("Space root must retain its complete Ed25519 identity")
                })?,
            );
        }
        root.ok_or_else(|| {
            anyhow::anyhow!("registry has no authenticated signing root for the selected Space")
        })
    })
}

pub(super) fn read_node_key(data: &Path) -> anyhow::Result<Keypair> {
    let path = data.join("node.key");
    let bytes = crate::secure_file::read_owner_only_optional(&path, 4 * 1024)?
        .ok_or_else(|| anyhow::anyhow!("retained node identity is missing"))?;
    let key = Keypair::from_protobuf_encoding(&bytes)?;
    anyhow::ensure!(
        key.key_type() == KeyType::Ed25519 && key.to_protobuf_encoding()? == bytes,
        "retained node identity must be canonical Ed25519"
    );
    Ok(key)
}

fn local_enrollment(
    space: SpaceId,
    root_public: [u8; 32],
    daemon: &Keypair,
) -> anyhow::Result<NodeEncryptionEnrollment> {
    sign_node_encryption_enrollment(
        daemon,
        space,
        PrincipalId::of_public_key(&root_public),
        derive_node_encryption_public(daemon, space)?,
    )
    .map_err(Into::into)
}

fn read_enrollment(path: &Path) -> anyhow::Result<NodeEncryptionEnrollment> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= NodeEncryptionEnrollment::MAX_ENCODED_BYTES as u64,
        "enrollment must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(NodeEncryptionEnrollment::MAX_ENCODED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 == metadata.len(),
        "enrollment changed while reading"
    );
    let enrollment = NodeEncryptionEnrollment::decode(&bytes)?;
    anyhow::ensure!(
        enrollment.verify_with(&StrictNodeEncryptionEnrollmentVerifier),
        "invalid node enrollment possession signature"
    );
    Ok(enrollment)
}

fn validate_enrollments(
    space: SpaceId,
    root_public: [u8; 32],
    daemon: &Keypair,
    enrollments: &[NodeEncryptionEnrollment],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        enrollments.len() == 3,
        "exactly three node enrollments are required"
    );
    let local = local_enrollment(space, root_public, daemon)?;
    let mut nodes = std::collections::BTreeSet::new();
    let mut registry_prefixes = std::collections::BTreeSet::new();
    for enrollment in enrollments {
        anyhow::ensure!(
            enrollment.space == space
                && enrollment.principal == local.principal
                && enrollment.verify_with(&StrictNodeEncryptionEnrollmentVerifier),
            "node enrollment has the wrong Space, root or signature"
        );
        anyhow::ensure!(
            nodes.insert(enrollment.node),
            "duplicate bootstrap node enrollment"
        );
        let peer = libp2p::PeerId::from_bytes(&enrollment.transport_peer_id)?;
        anyhow::ensure!(
            peer.to_bytes().as_slice() == enrollment.transport_peer_id.as_slice()
                && registry_prefixes.insert(vos::network::derive_node_prefix(&peer)),
            "bootstrap transport identities collide in the registry's compact node prefixes"
        );
    }
    anyhow::ensure!(
        enrollments.iter().find(|row| row.node == local.node) == Some(&local),
        "planning node enrollment does not match its retained transport and encryption identity"
    );
    Ok(())
}

pub(super) fn prepare_materials(
    materials: SystemBootstrapMaterials,
    operator: &Keypair,
    daemon: &Keypair,
    output: &Path,
) -> anyhow::Result<()> {
    let target = materials.authority_target();
    anyhow::ensure!(
        raw_public_key(operator)? == target.binding.public_key,
        "bootstrap materials belong to another operator"
    );
    let slot = system_logical_slot()?;
    let merge = Arc::new(
        Ed25519NodeMergeAuthenticator::new(daemon.clone())
            .map_err(|error| anyhow::anyhow!("construct bootstrap verifier: {error:?}"))?,
    );
    let daemon_public = raw_public_key(daemon)?;
    anyhow::ensure!(
        materials
            .replicas
            .member_by_node(merge.node())
            .is_some_and(|member| member.ed25519_public_key() == &daemon_public),
        "planning identity is outside the signed bootstrap roster"
    );
    let trust = Arc::new(SystemAgentTrust::new(
        slot,
        HostSpaceId(target.space.0),
        host_authority_binding(target.system_agent, target.binding),
    ));
    let (output, parent) = fresh_output_path(output)?;
    // Exclusive creation, rather than open-or-create, prevents a prior run's
    // durable certification from being overwritten or signed a second way.
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    parent.sync_all()?;
    let (_, _, _, file) = CleanSystemAgentFileStores::open_or_create(output.join("certification"))?
        .into_production_parts();
    let archive = CleanSystemAgentGenesisArchive::new(
        file,
        HostSpaceId(target.space.0),
        HostAgentId(target.system_agent.0),
        HostNodeId(merge.node().0),
        HostHash(target.binding.commitment().0),
        operator.clone(),
    )?;
    let prepared = materials.prepare(
        operator,
        slot,
        &mut |root, proposal: &_, catalog: &_| archive.certify_fresh(root, proposal, catalog),
        trust,
        merge,
    )?;
    let bytes = prepared.encode_import()?;
    write_fresh_file(
        &output.join("common.bundle"),
        &bytes,
        MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES,
    )
}

fn fresh_output_path(path: &Path) -> anyhow::Result<(PathBuf, File)> {
    output_path(path, true)
}

fn output_path(path: &Path, fresh: bool) -> anyhow::Result<(PathBuf, File)> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    anyhow::ensure!(
        path.file_name().is_some()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "output must name one new path without traversal"
    );
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output has no parent"))?;
    anyhow::ensure!(
        parent_path.canonicalize()? == parent_path,
        "output parent must be canonical"
    );
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent_path)?;
    let metadata = parent.metadata()?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.mode() & 0o777 == 0o700
            && metadata.uid() == unsafe { libc::geteuid() },
        "output parent must be an existing owner-only directory"
    );
    if fresh {
        anyhow::ensure!(
            !path.try_exists()?
                && fs::symlink_metadata(&path)
                    .err()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "output already exists; it will not be replaced"
        );
    }
    Ok((path, parent))
}

fn write_fresh_file(path: &Path, bytes: &[u8], maximum: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "output exceeds its canonical wire bound"
    );
    let (path, parent) = fresh_output_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

/// Export verified public OGAR bytes, never a key, member proof or readiness
/// grant. Exact existing output is re-synced; partial or substituted output is
/// preserved and refused. The caller retains its SCR1 and may choose a fresh
/// output path after an interrupted raw export.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn publish_shared_archive(path: &Path, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    use vos::service::ServiceWire as _;
    let maximum = vos::agent::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "archive output exceeds its wire bound"
    );
    vos::agent::genesis::AgentGenesisArchiveRecord::decode(bytes)
        .map_err(|error| anyhow::anyhow!("invalid archive output: {error:?}"))?;
    let (path, parent) = output_path(path, false)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_fresh_file(&path, bytes, maximum)?;
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&path)?;
            let opened = file.metadata()?;
            anyhow::ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && opened.is_file()
                    && opened.mode() & 0o777 == 0o600
                    && opened.uid() == unsafe { libc::geteuid() }
                    && opened.nlink() == 1
                    && (opened.dev(), opened.ino()) == (metadata.dev(), metadata.ino())
                    && opened.len() == bytes.len() as u64,
                "existing archive output has unsafe or incomplete physical identity"
            );
            let mut existing = Vec::new();
            (&file)
                .take(maximum as u64 + 1)
                .read_to_end(&mut existing)?;
            anyhow::ensure!(
                existing == bytes,
                "existing archive output differs; it will not be replaced"
            );
            file.sync_all()?;
            parent.sync_all()?;
            let current = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                current.is_file()
                    && !current.file_type().is_symlink()
                    && (current.dev(), current.ino()) == (opened.dev(), opened.ino())
                    && current.len() == opened.len(),
                "archive output changed during exact retry"
            );
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vos::Encode as _;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .parent()
                        .unwrap()
                        .join("target")
                });
            fs::create_dir_all(&target).unwrap();
            let root = target.canonicalize().unwrap().join("task-tmp");
            match fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("create disk-backed task directory: {error}"),
            }
            let path = root.join(format!(
                "bootstrap-prepare-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn identities() -> (Keypair, [Keypair; 3]) {
        (
            Keypair::ed25519_from_bytes([0x31; 32]).unwrap(),
            [0x32, 0x33, 0x34].map(|seed| Keypair::ed25519_from_bytes([seed; 32]).unwrap()),
        )
    }

    fn enrollments(
        space: SpaceId,
        operator: &Keypair,
        nodes: &[Keypair; 3],
    ) -> Vec<NodeEncryptionEnrollment> {
        nodes
            .iter()
            .map(|node| local_enrollment(space, raw_public_key(operator).unwrap(), node).unwrap())
            .collect()
    }

    fn materials(
        space: SpaceId,
        operator: &Keypair,
        nodes: &[Keypair; 3],
    ) -> SystemBootstrapMaterials {
        materials_with_runtime(
            space,
            operator,
            nodes,
            crate::bundled::root_signed_system_agent_runtime_package(operator).unwrap(),
        )
    }

    fn materials_with_runtime(
        space: SpaceId,
        operator: &Keypair,
        nodes: &[Keypair; 3],
        runtime: vos::agent::package_admission::AdmittedRuntimePackage,
    ) -> SystemBootstrapMaterials {
        assert_eq!(
            runtime.manifest().contract.lifecycle_abi,
            vos::agent::sdk::SYSTEM_OBSERVATION_ABI_ID,
        );
        SystemBootstrapMaterials::new(
            space,
            raw_public_key(operator).unwrap(),
            node_id_from_authenticated_peer(&nodes[0].public().to_peer_id()),
            runtime,
            crate::bundled::root_signed_actor_package(
                crate::bundled::system_authority_package_template(),
                SYSTEM_AUTHORITY_NAME,
                operator,
            )
            .unwrap(),
            crate::bundled::root_signed_actor_package(
                crate::bundled::system_catalog_package_template(),
                SYSTEM_CATALOG_NAME,
                operator,
            )
            .unwrap(),
            &enrollments(space, operator, nodes),
        )
        .unwrap()
    }

    #[test]
    fn certified_client_target_uses_exact_nondefault_system_and_keeps_local_image() {
        use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
        use vos::agent::sdk::{AgentProfile, Hash};
        let scratch = Scratch::new();
        let (operator, nodes) = identities();
        let space = SpaceId([0x3d; 32]);
        let image = crate::bundled::root_signed_agent_runtime_package(&operator).unwrap();
        assert_eq!(
            image.manifest().contract.lifecycle_abi,
            vos::agent::sdk::RUNTIME_ABI_ID,
        );
        let system_image =
            crate::bundled::root_signed_system_agent_runtime_package(&operator).unwrap();
        assert_eq!(
            system_image.manifest().contract.lifecycle_abi,
            vos::agent::sdk::SYSTEM_OBSERVATION_ABI_ID,
        );
        assert_ne!(system_image.program(), image.program());
        let mut envelope = PackageEnvelope::decode(system_image.exact_bytes()).unwrap();
        let PackageManifest::AgentRuntime(runtime) = &mut envelope.manifest else {
            unreachable!()
        };
        runtime.name = "certified-system-image-test".into();
        envelope.manifest.signing_mut().signature = operator
            .sign(&envelope.signing_bytes().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let runtime =
            vos::agent::package_admission::admit_runtime_package(&envelope.encode().unwrap())
                .unwrap();
        assert_ne!(runtime.deployment(), system_image.deployment());
        assert_eq!(runtime.program(), system_image.program());
        let materials = materials_with_runtime(space, &operator, &nodes, runtime);
        let expected = materials.authority_target();
        let output = scratch.0.join("prepared");
        prepare_materials(materials, &operator, &nodes[0], &output).unwrap();
        let bundle = output.join("common.bundle");
        let certified_bytes = fs::read(&bundle).unwrap();
        let config = super::super::super::local_config::LocalConfig {
            system_bootstrap_bundle: Some(PathBuf::from("prepared/common.bundle")),
            ..Default::default()
        };
        super::super::super::local_config::save(&scratch.0, &config).unwrap();
        let public = raw_public_key(&nodes[0]).unwrap();
        write_fresh_file(
            &scratch.0.join("node.key"),
            &nodes[0].to_protobuf_encoding().unwrap(),
            4096,
        )
        .unwrap();
        assert_eq!(
            super::super::client_system_authority_target(&scratch.0, space, &operator, public)
                .unwrap(),
            expected
        );
        let local = super::super::super::local_create::prepare_fresh_for_authority(
            &operator,
            expected,
            public,
            Hash([0x3e; 32]),
            std::num::NonZeroU64::new(1).unwrap(),
            10,
            30,
        )
        .unwrap();
        let (descriptor, call, local_runtime) = local.into_parts();
        assert_eq!(call.authority, expected);
        assert_eq!(descriptor.authority, expected.binding);
        assert_eq!(descriptor.identity.profile, AgentProfile::Local);
        assert_eq!(descriptor.identity.runtime_deployment, image.deployment());
        assert_eq!(local_runtime.exact_bytes(), image.exact_bytes());
        assert_ne!(
            descriptor.identity.runtime_deployment,
            expected.system_runtime_deployment
        );
        assert_eq!(fs::read(&bundle).unwrap(), certified_bytes);
        assert!(!scratch.0.join("agent-client").exists());
        assert!(
            !scratch
                .0
                .join(super::super::SYSTEM_AGENT_CONTROL_DIRECTORY)
                .exists()
        );

        let foreign = Keypair::ed25519_from_bytes([0x3f; 32]).unwrap();
        for (selected_space, selected_root, selected_node) in [
            (SpaceId([0x40; 32]), &operator, public),
            (space, &foreign, public),
            (space, &operator, raw_public_key(&nodes[1]).unwrap()),
        ] {
            assert!(
                super::super::client_system_authority_target(
                    &scratch.0,
                    selected_space,
                    selected_root,
                    selected_node,
                )
                .is_err()
            );
            assert_eq!(fs::read(&bundle).unwrap(), certified_bytes);
            assert!(!scratch.0.join("agent-client").exists());
        }
        // Actual persisted possession by a nonmember is still insufficient.
        fs::write(
            scratch.0.join("node.key"),
            foreign.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        assert!(
            super::super::client_system_authority_target(
                &scratch.0,
                space,
                &operator,
                raw_public_key(&foreign).unwrap(),
            )
            .is_err()
        );
        fs::write(
            scratch.0.join("node.key"),
            nodes[0].to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        let mut tampered = certified_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        for bad in [tampered, b"not a certified bootstrap".to_vec()] {
            fs::write(&bundle, &bad).unwrap();
            assert!(
                super::super::client_system_authority_target(&scratch.0, space, &operator, public,)
                    .is_err()
            );
            assert_eq!(fs::read(&bundle).unwrap(), bad);
            assert!(!scratch.0.join("agent-client").exists());
        }
        fs::remove_file(&bundle).unwrap();
        // Actual CLI preparation also refuses before opening its reservation,
        // rather than falling back or trying the offline transport endpoint.
        let address = "127.0.0.1:1".parse().unwrap();
        assert!(
            super::super::super::local_create::create_local(
                &scratch.0, address, &operator, space, public, false,
            )
            .is_err()
        );
        assert!(
            super::super::super::local_operation::authorize(
                &scratch.0, address, &operator, space, public, None,
            )
            .is_err()
        );
        assert!(!bundle.exists());
        assert!(!scratch.0.join("agent-client").exists());
    }

    #[test]
    fn certified_client_target_without_config_preserves_default_system_observation_binding() {
        let scratch = Scratch::new();
        let (operator, nodes) = identities();
        let space = SpaceId([0x41; 32]);
        let expected = materials(space, &operator, &nodes).authority_target();
        assert_eq!(
            super::super::client_system_authority_target(
                &scratch.0,
                space,
                &operator,
                raw_public_key(&nodes[0]).unwrap(),
            )
            .unwrap(),
            expected
        );
        assert!(!scratch.0.join("node.key").exists());
        assert!(!scratch.0.join("agent-client").exists());
        assert!(!super::super::super::local_config::path(&scratch.0).exists());
        drop(
            super::super::super::clean_store::ensure_private_directory(
                &scratch.0.join(super::super::SHARED_AGENT_HOST_DIRECTORY),
            )
            .unwrap(),
        );
        assert!(
            super::super::client_system_authority_target(
                &scratch.0,
                space,
                &operator,
                raw_public_key(&nodes[0]).unwrap(),
            )
            .is_err()
        );
        assert!(
            !scratch
                .0
                .join(super::super::SYSTEM_AGENT_CONTROL_DIRECTORY)
                .exists()
        );
        assert!(!scratch.0.join("agent-client").exists());
    }

    #[test]
    fn enrollment_files_require_canonical_wire_and_actual_possession_signature() {
        let scratch = Scratch::new();
        let (operator, nodes) = identities();
        let enrollment = local_enrollment(
            SpaceId([0x35; 32]),
            raw_public_key(&operator).unwrap(),
            &nodes[0],
        )
        .unwrap();
        let bytes = enrollment.encode().unwrap();
        let path = scratch.0.join("node.enrollment");
        write_fresh_file(&path, &bytes, NodeEncryptionEnrollment::MAX_ENCODED_BYTES).unwrap();
        assert_eq!(read_enrollment(&path).unwrap(), enrollment);
        assert!(
            write_fresh_file(
                &path,
                b"replacement",
                NodeEncryptionEnrollment::MAX_ENCODED_BYTES
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        for (name, bad) in [
            ("trailing", {
                let mut wire = bytes.clone();
                wire.push(0);
                wire
            }),
            ("signature", {
                let mut wire = bytes.clone();
                *wire.last_mut().unwrap() ^= 1;
                wire
            }),
            (
                "oversized",
                vec![0; NodeEncryptionEnrollment::MAX_ENCODED_BYTES + 1],
            ),
        ] {
            let path = scratch.0.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&bad).unwrap();
            assert!(read_enrollment(&path).is_err(), "{name}");
        }
        let alias = scratch.0.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_enrollment(&alias).is_err());
    }

    #[test]
    fn roster_validation_refuses_wrong_scope_duplicate_and_wrong_local_encryption() {
        let (operator, nodes) = identities();
        let public = raw_public_key(&operator).unwrap();
        let space = SpaceId([0x36; 32]);
        let good = enrollments(space, &operator, &nodes);
        validate_enrollments(space, public, &nodes[0], &good).unwrap();
        let mut reversed = good.clone();
        reversed.reverse();
        validate_enrollments(space, public, &nodes[0], &reversed).unwrap();
        assert!(validate_enrollments(space, public, &nodes[0], &good[..2]).is_err());
        assert!(validate_enrollments(space, public, &nodes[0], &[good[0]; 3]).is_err());
        assert!(validate_enrollments(SpaceId([0x37; 32]), public, &nodes[0], &good).is_err());
        let foreign = Keypair::ed25519_from_bytes([0x38; 32]).unwrap();
        assert!(
            validate_enrollments(space, raw_public_key(&foreign).unwrap(), &nodes[0], &good)
                .is_err()
        );
        assert!(validate_enrollments(space, public, &foreign, &good).is_err());
        let mut altered = good.clone();
        altered[1] = local_enrollment(SpaceId([0x37; 32]), public, &nodes[1]).unwrap();
        assert!(validate_enrollments(space, public, &nodes[0], &altered).is_err());
        altered = good.clone();
        altered[0] = sign_node_encryption_enrollment(
            &nodes[0],
            space,
            PrincipalId::of_public_key(&public),
            derive_node_encryption_public(&nodes[1], space).unwrap(),
        )
        .unwrap();
        assert!(altered[0].verify_with(&StrictNodeEncryptionEnrollmentVerifier));
        assert!(validate_enrollments(space, public, &nodes[0], &altered).is_err());
    }

    #[test]
    fn independently_signed_nodes_with_colliding_registry_prefixes_are_refused() {
        let (operator, nodes) = identities();
        let space = SpaceId([0x3b; 32]);
        let mut by_prefix = std::collections::BTreeMap::new();
        // A bounded birthday search uses genuine distinct Ed25519 identities,
        // not a forged NEN1 prefix field (the enrollment has no such field).
        let pair = (0u32..4_096)
            .find_map(|value| {
                let mut seed = [0x3c; 32];
                seed[..4].copy_from_slice(&value.to_le_bytes());
                let key = Keypair::ed25519_from_bytes(seed).unwrap();
                let prefix = vos::network::derive_node_prefix(&key.public().to_peer_id());
                by_prefix
                    .insert(prefix, key.clone())
                    .map(|prior| (prior, key))
            })
            .expect(
                "bounded deterministic test identities must contain a compact-prefix collision",
            );
        let roster = [pair.0, pair.1, nodes[0].clone()];
        assert_ne!(
            roster[0].public().to_peer_id(),
            roster[1].public().to_peer_id()
        );
        let signed = enrollments(space, &operator, &roster);
        assert!(
            signed
                .iter()
                .all(|row| row.verify_with(&StrictNodeEncryptionEnrollmentVerifier))
        );
        assert!(
            signed
                .iter()
                .map(|row| row.node)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 3
        );
        let error = validate_enrollments(
            space,
            raw_public_key(&operator).unwrap(),
            &roster[0],
            &signed,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("compact node prefixes"),
            "{error:#}"
        );
    }

    #[test]
    fn offline_common_bundle_rebinds_without_recertifying_or_overwriting() {
        let scratch = Scratch::new();
        let (operator, nodes) = identities();
        let space = SpaceId([0x39; 32]);
        let output = scratch.0.join("prepared");
        prepare_materials(
            materials(space, &operator, &nodes),
            &operator,
            &nodes[0],
            &output,
        )
        .unwrap();
        let bytes = fs::read(output.join("common.bundle")).unwrap();
        let archive_path = output
            .join("certification")
            .join("system-agent.genesis-archive");
        let certified = fs::read(&archive_path).unwrap();
        let baseline = super::super::read_certified_bootstrap_bundle(
            &output.join("common.bundle"),
            space.0,
            &operator,
            &nodes[0],
        )
        .unwrap();
        for node in &nodes {
            let rebound = super::super::read_certified_bootstrap_bundle(
                &output.join("common.bundle"),
                space.0,
                &operator,
                node,
            )
            .unwrap();
            assert_eq!(
                rebound.plan().pins().node(),
                node_id_from_authenticated_peer(&node.public().to_peer_id())
            );
            assert_eq!(rebound.provision().root(), baseline.provision().root());
            assert_eq!(
                rebound.provision().evidence(),
                baseline.provision().evidence()
            );
            assert_eq!(
                rebound.provision().proposal().create(),
                baseline.provision().proposal().create()
            );
        }
        assert!(
            prepare_materials(
                materials(space, &operator, &nodes),
                &operator,
                &nodes[0],
                &output
            )
            .is_err()
        );
        assert_eq!(fs::read(output.join("common.bundle")).unwrap(), bytes);
        assert_eq!(fs::read(archive_path).unwrap(), certified);
        let foreign = Keypair::ed25519_from_bytes([0x3a; 32]).unwrap();
        let refused = scratch.0.join("refused");
        assert!(
            prepare_materials(
                materials(space, &operator, &nodes),
                &foreign,
                &nodes[0],
                &refused
            )
            .is_err()
        );
        assert!(!refused.exists());
        assert!(
            prepare_materials(
                materials(space, &operator, &nodes),
                &operator,
                &foreign,
                &refused
            )
            .is_err()
        );
        assert!(!refused.exists());
    }

    fn root_record(operator: &Keypair) -> ([u8; 32], Vec<u8>) {
        let message = vos::value::Msg::new("set_root")
            .with("root", operator.public().to_peer_id().to_bytes())
            .with("schema_version", vos::registry::REGISTRY_SCHEMA_VERSION)
            .with("schema_hash", vos::registry::REGISTRY_SCHEMA_HASH.to_vec());
        let mut message_bytes = vec![vos::value::TAG_DYNAMIC];
        message_bytes.extend_from_slice(&message.encode());
        let event = vos::effect_log::CrdtEvent::new(
            [0x3b; 32],
            1,
            vos::effect_log::EffectLog::for_msg(message_bytes),
        );
        let payload = event.to_bytes();
        let mut node = (payload.len() as u64).to_le_bytes().to_vec();
        node.extend_from_slice(&payload);
        node.extend_from_slice(&0u64.to_le_bytes());
        (vos::crypto::blake2b_hash(b"", &[&node]), node)
    }

    #[test]
    fn offline_root_selection_requires_actual_space_genesis_not_ambient_operator() {
        let scratch = Scratch::new();
        let (operator, _) = identities();
        let foreign = Keypair::ed25519_from_bytes([0x3c; 32]).unwrap();
        let (cid, node) = root_record(&operator);
        let (foreign_cid, foreign_node) = root_record(&foreign);
        let agents = scratch.0.join("agents");
        fs::DirBuilder::new().mode(0o700).create(&agents).unwrap();
        let path = agents.join(format!(
            "{:08x}.redb",
            vos::abi::service::ServiceId::REGISTRY.0
        ));
        {
            let db = redb::Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(DAG_TABLE).unwrap();
                table.insert(cid.as_slice(), node.as_slice()).unwrap();
                table
                    .insert(foreign_cid.as_slice(), foreign_node.as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        let space = SpaceId(crate::commands::space::common::derive_space_id(&cid));
        let source_bytes = fs::read(&path).unwrap();
        let audit_parent = scratch.0.join("audit");
        assert_eq!(
            read_space_root_with_audit_parent(&scratch.0, space, &audit_parent).unwrap(),
            raw_public_key(&operator).unwrap()
        );
        assert_eq!(fs::read(&path).unwrap(), source_bytes);
        assert_ne!(
            read_space_root_with_audit_parent(&scratch.0, space, &audit_parent).unwrap(),
            raw_public_key(&foreign).unwrap()
        );
        assert!(
            read_space_root_with_audit_parent(&scratch.0, SpaceId([0x3d; 32]), &audit_parent)
                .is_err()
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            source_bytes,
            "accepted and refused scope inspection must leave source bytes unchanged"
        );
        assert_eq!(
            fs::read_dir(&audit_parent).unwrap().count(),
            0,
            "the exact private audit copies must be removed"
        );
        let saved = agents.join("saved.redb");
        fs::rename(&path, &saved).unwrap();
        assert!(read_space_root_with_audit_parent(&scratch.0, space, &audit_parent).is_err());
        assert!(
            !path.exists(),
            "verification must not initialize an absent database"
        );
        std::os::unix::fs::symlink(&saved, &path).unwrap();
        assert!(read_space_root_with_audit_parent(&scratch.0, space, &audit_parent).is_err());
        assert_eq!(fs::read(&saved).unwrap(), source_bytes);
    }

    #[test]
    fn fresh_output_refuses_aliases_existing_paths_and_public_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new();
        let path = scratch.0.join("output");
        write_fresh_file(&path, b"retained", 16).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(write_fresh_file(&path, b"replacement", 16).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"retained");
        let alias = scratch.0.join("dangling");
        std::os::unix::fs::symlink(scratch.0.join("absent"), &alias).unwrap();
        assert!(write_fresh_file(&alias, b"replacement", 16).is_err());
        let public = scratch.0.join("public");
        fs::DirBuilder::new().mode(0o700).create(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(write_fresh_file(&public.join("output"), b"bytes", 16).is_err());
        assert!(!public.join("output").exists());
        assert!(write_fresh_file(&scratch.0.join("oversized"), b"larger", 1).is_err());
        assert!(!scratch.0.join("oversized").exists());
    }
}
