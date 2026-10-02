//! Fresh registry-only member preparation, never node recovery or migration.
//! Uses the existing backup envelope; only its exact fresh genesis DAG is
//! rehydrated. Source cached state, sequence counters and secrets are not copied.

use std::ffi::CString;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use libp2p::PeerId;
use libp2p::identity::Keypair;
use redb::ReadableTable as _;
use vos::abi::service::ServiceId;
use vos::commit::{CommitStrategy as _, CrdtCommit, DAG_TABLE};
use vos::node::{AgentConfig, Consistency, VosNode};
use vos::registry::{NODE_ROLE_VOTER, OP_SIG_LEN, RegistryRef};

use super::{BackupManifest, MANIFEST_FILE, MAX_MANIFEST_BYTES};
use crate::blob_store::BlobHash;
use crate::commands::space::{common, local_config};
use crate::spaces_index::{self, SpaceEntry};

// The invoke queue may initialize the Registry with set_root before its
// pending empty kick runs. The later unchanged kick then appends no node.
// Both actual schedules retain the same three exact genesis operations;
// only one initial empty on-start node may additionally be present.
const FRESH_GENESIS_OPERATION_COUNT: usize = 3;
const MAX_FRESH_GENESIS_NODE_COUNT: usize = FRESH_GENESIS_OPERATION_COUNT + 1;
const MAX_SEED_HISTORY_BYTES: usize = 1024 * 1024;
const MAX_SEED_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SEED_STATE_ROW_BYTES: usize = 2 * 1024 * 1024;
const STATE_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("state");

#[derive(clap::Args, Debug)]
pub struct PrepareBootstrapMemberArgs {
    /// New local name; no existing Space/index entry can be replaced.
    pub name: String,
    /// Verified registry-only backup taken immediately after `space new`.
    pub backup: PathBuf,
    /// Independently retained exact Space ID, as 64 lowercase hexadecimal characters.
    #[arg(long)]
    pub space_id: String,
    /// Independently retained canonical full Ed25519 Space-root PeerId.
    #[arg(long)]
    pub root_peer_id: String,
    /// Fresh node-local directory. This tool never starts the System Agent.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

/// Only this private audit produces a seed. Possessing a backup is not node
/// admission; callers receive neither source node keys nor a serving route.
struct VerifiedFreshRegistrySeed {
    manifest: BackupManifest,
    manifest_hash: [u8; 32],
    space: [u8; 32],
    root_peer: PeerId,
    creator_peer: PeerId,
    nodes: Vec<([u8; 32], Vec<u8>)>,
}

pub(crate) fn prepare_bootstrap_member(args: PrepareBootstrapMemberArgs) -> anyhow::Result<()> {
    let space = parse_space_id(&args.space_id)?;
    let root = parse_root_peer(&args.root_peer_id)?;
    let seed = audit_seed(&args.backup, space, root, &crate::paths::cache_root())?;
    let _space_lock = crate::commands::space::space_lock::SpaceDataLock::exclusive(&space)?;
    let destination = args
        .data_dir
        .unwrap_or_else(|| crate::paths::space_dir(&space));
    let (entry, peer) = publish_fresh_member(
        &args.backup,
        seed,
        &args.name,
        &destination,
        &crate::blob_store::cache_dir(),
        &crate::paths::spaces_index_path(),
    )?;
    println!(
        "Prepared '{}' for Space {} at {} with fresh node {}. No System Agent was started and no live membership was granted. Export its bootstrap enrollment next.",
        entry.name, entry.id, entry.data_dir, peer,
    );
    Ok(())
}

fn parse_space_id(value: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Space ID must be canonical lowercase hexadecimal"
    );
    let bytes: [u8; 32] = hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Space ID must contain 32 bytes"))?;
    anyhow::ensure!(bytes != [0; 32], "Space ID must be nonzero");
    Ok(bytes)
}

fn parse_root_peer(value: &str) -> anyhow::Result<PeerId> {
    let peer: PeerId = value.parse()?;
    anyhow::ensure!(
        peer.to_string() == value
            && vos::registry::ed25519_pubkey_from_peer_id(&peer.to_bytes()).is_some(),
        "Space root must be a canonical full Ed25519 PeerId"
    );
    Ok(peer)
}

fn read_seed_manifest(archive: &Path) -> anyhow::Result<BackupManifest> {
    let file = super::open_regular_file_nofollow(&archive.join(MANIFEST_FILE))?;
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_MANIFEST_BYTES,
        "backup manifest exceeds its bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "backup manifest changed during read"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn require_seed_envelope(
    archive: &Path,
    manifest: &BackupManifest,
    space: [u8; 32],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        manifest.format == super::ARCHIVE_FORMAT
            && manifest.space.id_bytes() == Some(space)
            && manifest.files.len() == 2,
        "fresh member requires the current two-file registry-only backup for its exact Space"
    );
    let bundled = crate::bundled::registry_elf()
        .ok_or_else(|| anyhow::anyhow!("bundled registry artifact is unavailable"))?;
    let hash = BlobHash::of(bundled).to_hex();
    anyhow::ensure!(
        manifest.space.registry_hash == hash,
        "seed registry is not this binary's exact bundled artifact"
    );
    for file in &manifest.files {
        let maximum = if file.path == super::registry_db_wire() {
            MAX_SEED_DATABASE_BYTES
        } else if file.path == format!("blobs/{hash}") {
            bundled.len() as u64
        } else {
            anyhow::bail!("fresh member seed contains non-genesis deployment data");
        };
        let opened = super::open_regular_file_nofollow(&super::wire_to_path(archive, &file.path)?)?;
        anyhow::ensure!(
            file.bytes != 0 && file.bytes <= maximum && opened.metadata()?.len() == file.bytes,
            "fresh member seed file exceeds its exact bound"
        );
    }
    Ok(())
}

fn audit_seed(
    archive: &Path,
    space: [u8; 32],
    root_peer: PeerId,
    audit_parent: &Path,
) -> anyhow::Result<VerifiedFreshRegistrySeed> {
    // Apply the narrower quotas before the generic integrity verifier hashes
    // any payload. Its ordinary backup/restore acceptance rules stay unchanged.
    let preflight = read_seed_manifest(archive)?;
    require_seed_envelope(archive, &preflight, space)?;
    let manifest_hash = super::hash_file(&archive.join(MANIFEST_FILE))?;
    let manifest = super::verify_archive(archive)?;
    require_seed_envelope(archive, &manifest, space)?;
    anyhow::ensure!(
        super::hash_file(&archive.join(MANIFEST_FILE))? == manifest_hash,
        "seed manifest changed during verification"
    );
    let creator_peer: PeerId = manifest.recovery.node_peer_id.parse()?;
    anyhow::ensure!(
        vos::registry::ed25519_pubkey_from_peer_id(&creator_peer.to_bytes())
            .is_some_and(|key| hex::encode(key) == manifest.recovery.node_public_key),
        "seed creator identity metadata is inconsistent"
    );
    let database_path = super::wire_to_path(archive, &super::registry_db_wire())?;
    let record = manifest
        .files
        .iter()
        .find(|file| file.path == super::registry_db_wire())
        .ok_or_else(|| anyhow::anyhow!("seed has no registry database"))?;
    let expected_hash = hex::decode(&record.blake2b_256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed database has an invalid digest"))?;
    let nodes = super::with_registry_audit_copy(
        &database_path,
        audit_parent,
        Some(expected_hash),
        |db| {
            let mut nodes = Vec::with_capacity(MAX_FRESH_GENESIS_NODE_COUNT);
            {
                let transaction = db.begin_read()?;
                let metadata = transaction.open_table(STATE_TABLE)?;
                for (index, row) in metadata.iter()?.enumerate() {
                    let (key, value) = row?;
                    anyhow::ensure!(
                        index < 16 && value.value().len() <= MAX_SEED_STATE_ROW_BYTES,
                        "seed cached metadata exceeds its fresh-deployment bound"
                    );
                    if key.value() == vos::commit::ROOTS_KEY {
                        anyhow::ensure!(
                            value.value().len() == 40 && value.value()[..8] == 1u64.to_le_bytes(),
                            "fresh genesis must have one canonical registry head"
                        );
                    }
                }
                let table = transaction.open_table(DAG_TABLE)?;
                let mut bytes = 0usize;
                let validator = common::genesis_node_validator(space);
                for row in table.iter()? {
                    anyhow::ensure!(
                        nodes.len() < MAX_FRESH_GENESIS_NODE_COUNT,
                        "seed contains deployment history beyond fresh space genesis"
                    );
                    let (key, value) = row?;
                    let cid: [u8; 32] = key
                        .value()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("seed node has an invalid CID"))?;
                    bytes = bytes
                        .checked_add(value.value().len())
                        .ok_or_else(|| anyhow::anyhow!("seed history size overflow"))?;
                    anyhow::ensure!(
                        bytes <= MAX_SEED_HISTORY_BYTES
                            && validator(&cid, value.value())
                            && vos::crypto::blake2b_hash::<32>(b"", &[value.value()]) == cid,
                        "seed contains invalid, foreign or oversized registry history"
                    );
                    nodes.push((cid, value.value().to_vec()));
                }
            }
            anyhow::ensure!(
                (FRESH_GENESIS_OPERATION_COUNT..=MAX_FRESH_GENESIS_NODE_COUNT)
                    .contains(&nodes.len()),
                "seed must contain the exact three genesis operations and at most one initial kick; found {} nodes",
                nodes.len(),
            );
            let origin = vos::service::NodeId::of_authenticated_peer(&creator_peer.to_bytes()).0;
            let source = CrdtCommit::from_db_arc(db, origin)?;
            let logs = source.replay_logs()?;
            anyhow::ensure!(
                logs.len() == nodes.len(),
                "seed history is incomplete, unreachable or quarantined"
            );
            validate_fresh_logs(&nodes, &logs, space, &root_peer, &creator_peer)?;
            Ok(nodes)
        },
    )?;
    // Re-read the complete existing envelope after the scoped source read;
    // hash equality closes substitution and proves source bytes were retained.
    super::verify_archive(archive)?;
    anyhow::ensure!(
        super::hash_file(&archive.join(MANIFEST_FILE))? == manifest_hash,
        "seed changed during history audit"
    );
    Ok(VerifiedFreshRegistrySeed {
        manifest,
        manifest_hash,
        space,
        root_peer,
        creator_peer,
        nodes,
    })
}

fn validate_fresh_logs(
    nodes: &[([u8; 32], Vec<u8>)],
    logs: &[vos::effect_log::EffectLog],
    space: [u8; 32],
    root: &PeerId,
    creator: &PeerId,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        nodes.len() == logs.len()
            && (FRESH_GENESIS_OPERATION_COUNT..=MAX_FRESH_GENESIS_NODE_COUNT).contains(&logs.len()),
        "fresh genesis must contain the exact three operations with only an optional initial kick"
    );
    let expected = [
        None,
        Some("set_root"),
        Some("set_space_id"),
        Some("add_node"),
    ];
    let expected = &expected[MAX_FRESH_GENESIS_NODE_COUNT - logs.len()..];
    let root_bytes = root.to_bytes();
    let root_public = vos::registry::ed25519_pubkey_from_peer_id(&root_bytes)
        .ok_or_else(|| anyhow::anyhow!("root lacks an Ed25519 key"))?;
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&root_public)?;
    let public = libp2p::identity::PublicKey::from(public);
    for (index, log) in logs.iter().enumerate() {
        anyhow::ensure!(
            log.replies.is_empty() && log.invoke_effects.is_empty(),
            "fresh genesis cannot retain child execution or arbitrary reply history"
        );
        let request = vos::node::registry_replay_request(log).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            request.as_ref().map(|request| request.name.as_str()) == expected[index],
            "seed does not reproduce the exact fresh genesis operation order"
        );
        let Some(request) = request else {
            continue;
        };
        match request.name.as_str() {
            "set_root" => {
                anyhow::ensure!(
                    request.args.get_bytes("root").as_deref() == Some(root_bytes.as_slice()),
                    "seed signing root differs from the independently retained root"
                );
                let matching = nodes
                    .iter()
                    .filter(|(cid, wire)| {
                        common::registry_genesis_cid(cid, wire)
                            .is_some_and(|actual| common::derive_space_id(&actual) == space)
                    })
                    .count();
                anyhow::ensure!(
                    matching == 1,
                    "seed lacks its exact authenticated Space genesis CID"
                );
            }
            "set_space_id" => anyhow::ensure!(
                request.args.get_bytes("space_id").as_deref() == Some(space.as_slice()),
                "seed Space anchor differs from its genesis"
            ),
            "add_node" => {
                let prefix = vos::network::derive_node_prefix(creator) as u32;
                let peer = creator.to_bytes();
                anyhow::ensure!(
                    request.args.get_u32("prefix") == Some(prefix)
                        && request.args.get_bytes("peer_id").as_deref() == Some(peer.as_slice())
                        && request.args.get_u8("role") == Some(NODE_ROLE_VOTER),
                    "seed contains another node admission or deployment history"
                );
                let auth = request
                    .args
                    .get_bytes("auth")
                    .ok_or_else(|| anyhow::anyhow!("source creator admission has no signature"))?;
                anyhow::ensure!(
                    auth.len() == root_bytes.len() + OP_SIG_LEN
                        && auth[..root_bytes.len()] == root_bytes,
                    "source creator admission is not signed by the selected root"
                );
                let signed = vos::registry::registry_mutation_signed_bytes(
                    &space,
                    "add_node",
                    &[&prefix.to_le_bytes(), &peer, &[NODE_ROLE_VOTER]],
                );
                anyhow::ensure!(
                    public.verify(&signed, &auth[root_bytes.len()..]),
                    "source creator admission signature is invalid"
                );
            }
            _ => anyhow::bail!("fresh genesis contains unsupported history"),
        }
    }
    Ok(())
}

fn publish_fresh_member(
    archive: &Path,
    seed: VerifiedFreshRegistrySeed,
    name: &str,
    destination: &Path,
    cache: &Path,
    index_path: &Path,
) -> anyhow::Result<(SpaceEntry, PeerId)> {
    anyhow::ensure!(!name.is_empty(), "member name must be nonempty");
    let destination = spaces_index::normalize_data_directory(destination)?;
    anyhow::ensure!(
        !super::path_entry_exists(&destination)?,
        "fresh member destination already exists; nothing will be replaced"
    );
    let mut index = spaces_index::LockedSpacesIndex::acquire_from(index_path)?;
    anyhow::ensure!(
        !index
            .spaces
            .iter()
            .any(|entry| entry.id_bytes() == Some(seed.space) || entry.name == name),
        "fresh member requires a new local Space ID/name; no index entry will be replaced"
    );
    let mut entry = spaces_index::entry_for_at(&seed.space, name, &destination)?;
    entry.registry_hash = seed.manifest.space.registry_hash.clone();
    index.validate_upsert(&entry)?;
    super::reject_restore_overlap(archive, &destination)?;
    let stage = super::temporary_sibling(&destination, "fresh-member-preparation")?;
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let prepared = (|| -> anyhow::Result<PeerId> {
        // Only a fresh actual local identity is generated. The source creator
        // key and the Space operator's private identity are never read/copied.
        let node = loop {
            let node = Keypair::generate_ed25519();
            if vos::network::derive_node_prefix(&node.public().to_peer_id())
                != vos::network::derive_node_prefix(&seed.creator_peer)
            {
                break node;
            }
        };
        let peer = node.public().to_peer_id();
        let key_bytes = node.to_protobuf_encoding()?;
        crate::secure_file::write_owner_only_atomic(&stage.join("node.key"), &key_bytes)?;
        let agents = stage.join("agents");
        fs::DirBuilder::new().mode(0o700).create(&agents)?;
        let registry_path = agents.join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
        let origin = vos::service::NodeId::of_authenticated_peer(&peer.to_bytes()).0;
        let mut store = CrdtCommit::open(&registry_path, origin)?;
        store.set_node_validator(Some(common::genesis_node_validator(seed.space)));
        for (cid, bytes) in &seed.nodes {
            anyhow::ensure!(
                store.insert_node(cid, bytes)?,
                "fresh genesis node was refused by typed ingestion"
            );
        }
        store.compact_roots()?;
        anyhow::ensure!(
            store.replay_logs()?.len() == seed.nodes.len(),
            "rehydrated genesis has an incomplete closure"
        );
        drop(store);
        replay_and_verify(
            &stage,
            seed.space,
            &seed.root_peer,
            &seed.creator_peer,
            &peer,
        )?;
        local_config::save(&stage, &local_config::LocalConfig::for_new_space())?;
        super::verify_archive(archive)?;
        anyhow::ensure!(
            super::hash_file(&archive.join(MANIFEST_FILE))? == seed.manifest_hash,
            "source seed changed before publication"
        );
        super::restore_blobs_to_cache(archive, &seed.manifest, cache)?;
        for path in [
            stage.join("node.key"),
            local_config::path(&stage),
            registry_path,
        ] {
            fs::File::open(path)?.sync_all()?;
        }
        super::sync_tree_directories(&stage)?;
        activate_fresh(&stage, &destination)?;
        super::sync_directory(super::usable_parent(&destination))?;
        spaces_index::upsert(&mut index, entry.clone());
        index.save()?;
        Ok(peer)
    })();
    let peer = prepared.with_context(|| format!("fresh member was not acknowledged; inspect retained {} and {} before retrying; neither is automatically removed or overwritten", stage.display(), destination.display()))?;
    Ok((entry, peer))
}

fn replay_and_verify(
    data: &Path,
    space: [u8; 32],
    root: &PeerId,
    creator: &PeerId,
    member: &PeerId,
) -> anyhow::Result<()> {
    let elf = crate::bundled::registry_elf()
        .ok_or_else(|| anyhow::anyhow!("bundled registry is unavailable"))?;
    let blob = vos_pvm_compiler::link_elf(elf)
        .map_err(|error| anyhow::anyhow!("transpile bundled registry: {error:?}"))?;
    let mut node = VosNode::with_prefix(vos::network::derive_node_prefix(member));
    node.register_at_id(
        AgentConfig::new(blob)
            .with_name(vos::node::REGISTRY_AGENT_NAME)
            .with_consistency(Consistency::Crdt)
            .with_replication_id(common::registry_replication_id(&space))
            .with_node_validator(common::genesis_node_validator(space))
            .persist(data),
        ServiceId::REGISTRY,
    );
    let registry = RegistryRef::at(ServiceId::REGISTRY);
    let verified = (|| -> anyhow::Result<()> {
        anyhow::ensure!(
            vos::block_on(registry.protocol(&mut &node))?.is_current(),
            "seed replay did not retain the current registry protocol"
        );
        anyhow::ensure!(
            vos::block_on(registry.root(&mut &node))? == root.to_bytes()
                && vos::block_on(registry.space_id(&mut &node))? == space,
            "seed replay changed its exact Space/root anchors"
        );
        anyhow::ensure!(
            vos::block_on(registry.programs_all(&mut &node))?.is_empty()
                && vos::block_on(registry.agents_all(&mut &node))?.is_empty()
                && vos::block_on(registry.system_actors_all(&mut &node))?.is_empty(),
            "seed replay contains migrated actors or program history"
        );
        let members = vos::block_on(registry.members_all(&mut &node))?;
        anyhow::ensure!(
            members.len() == 1
                && members[0].kind == vos::registry::MEMBER_KIND_NODE
                && members[0].key == creator.to_bytes()
                && members[0].prefix == vos::network::derive_node_prefix(creator)
                && members[0].role == NODE_ROLE_VOTER,
            "seed replay does not retain exactly its source creator admission"
        );
        anyhow::ensure!(
            vos::block_on(
                registry.node_role(&mut &node, vos::network::derive_node_prefix(member) as u64)
            )? == 0,
            "fresh member preparation must not grant live registry membership"
        );
        Ok(())
    })();
    node.shutdown();
    let results = node.collect_checked()?;
    for result in results {
        anyhow::ensure!(
            result.panics == 0 && result.error.is_none(),
            "registry-only preparation failed: {:?}",
            result.error
        );
    }
    verified
}

fn activate_fresh(stage: &Path, destination: &Path) -> anyhow::Result<()> {
    let stage = CString::new(stage.as_os_str().as_encoded_bytes())?;
    let destination = CString::new(destination.as_os_str().as_encoded_bytes())?;
    // SAFETY: both C strings live through the call. NOREPLACE makes even a
    // concurrently created destination fail closed; no prior member is moved.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            stage.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

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
            let parent = target.canonicalize().unwrap().join("task-tmp");
            match fs::DirBuilder::new().mode(0o700).create(&parent) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("create disk-backed test directory: {error}"),
            }
            let root = parent.join(format!(
                "fresh-bootstrap-member-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct Fixture {
        _scratch: Scratch,
        archive: PathBuf,
        data: PathBuf,
        cache: PathBuf,
        space: [u8; 32],
        operator: Keypair,
        creator: Keypair,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = Scratch::new();
            let data = scratch.0.join("source");
            let cache = scratch.0.join("cache");
            fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&data.join("agents"))
                .unwrap();
            fs::DirBuilder::new().mode(0o700).create(&cache).unwrap();
            let operator = Keypair::ed25519_from_bytes([0x71; 32]).unwrap();
            let creator = Keypair::ed25519_from_bytes([0x72; 32]).unwrap();
            let peer = creator.public().to_peer_id();
            let prefix = vos::network::derive_node_prefix(&peer);
            let elf = crate::bundled::registry_elf().unwrap();
            let blob = vos_pvm_compiler::link_elf(elf).unwrap();
            let registry_hash = BlobHash::of(elf);
            fs::write(cache.join(registry_hash.to_hex()), elf).unwrap();
            let mut node = VosNode::with_prefix(prefix);
            let origin =
                vos::crypto::blake2b_hash(b"vos/space-genesis-origin/v1", &[&peer.to_bytes()]);
            node.register_at_id(
                AgentConfig::new(blob.clone())
                    .with_name(vos::node::REGISTRY_AGENT_NAME)
                    .with_consistency(Consistency::Crdt)
                    .with_replication_id(origin)
                    .persist(&data),
                ServiceId::REGISTRY,
            );
            let registry = RegistryRef::at(ServiceId::REGISTRY);
            assert_eq!(
                vos::block_on(
                    registry.set_root(&mut &node, operator.public().to_peer_id().to_bytes())
                )
                .unwrap(),
                vos::registry::Status::Ok
            );
            node.shutdown();
            for result in node.collect_checked().unwrap() {
                assert!(result.error.is_none());
            }
            let cid = crate::commands::space::new::read_genesis_root(
                &data
                    .join("agents")
                    .join(format!("{:08x}.redb", ServiceId::REGISTRY.0)),
            )
            .unwrap();
            let space = common::derive_space_id(&cid);
            let mut node = VosNode::with_prefix(prefix);
            node.register_at_id(
                AgentConfig::new(blob)
                    .with_name(vos::node::REGISTRY_AGENT_NAME)
                    .with_consistency(Consistency::Crdt)
                    .with_replication_id(space)
                    .with_node_validator(common::genesis_node_validator(space))
                    .persist(&data),
                ServiceId::REGISTRY,
            );
            assert_eq!(
                vos::block_on(registry.set_space_id(&mut &node, space.to_vec())).unwrap(),
                vos::registry::Status::Ok
            );
            let auth = crate::commands::space::op_sign::op_auth(
                &operator,
                &space,
                "add_node",
                &[
                    &(prefix as u32).to_le_bytes(),
                    &peer.to_bytes(),
                    &[NODE_ROLE_VOTER],
                ],
            )
            .unwrap();
            assert_eq!(
                vos::block_on(registry.add_node(
                    &mut &node,
                    prefix as u32,
                    peer.to_bytes(),
                    NODE_ROLE_VOTER,
                    auth
                ))
                .unwrap(),
                vos::registry::Status::Ok
            );
            node.shutdown();
            for result in node.collect_checked().unwrap() {
                assert!(result.error.is_none());
            }
            crate::secure_file::write_owner_only_atomic(
                &data.join("node.key"),
                &creator.to_protobuf_encoding().unwrap(),
            )
            .unwrap();
            let mut entry = spaces_index::entry_for_at(&space, "source", &data).unwrap();
            entry.registry_hash = registry_hash.to_hex();
            let archive = scratch.0.join("registry-seed");
            super::super::create_archive(&entry, &archive, &cache).unwrap();
            Self {
                _scratch: scratch,
                archive,
                data,
                cache,
                space,
                operator,
                creator,
            }
        }

        fn seed(&self) -> VerifiedFreshRegistrySeed {
            audit_seed(
                &self.archive,
                self.space,
                self.operator.public().to_peer_id(),
                &self.cache,
            )
            .unwrap()
        }

        fn index(&self, name: &str) -> PathBuf {
            let config = self._scratch.0.join(name);
            fs::DirBuilder::new().mode(0o700).create(&config).unwrap();
            config.join("spaces.toml")
        }
    }

    fn tree(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn collect(root: &Path, at: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(at).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    collect(root, &entry.path(), result);
                } else {
                    result.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut result = BTreeMap::new();
        collect(path, path, &mut result);
        result
    }

    #[test]
    fn genuine_registry_seed_prepares_same_space_with_two_distinct_fresh_node_keys() {
        let fixture = Fixture::new();
        let source = tree(&fixture.archive);
        let seal = fixture
            .data
            .join("agents")
            .join(format!("{:08x}.seal", ServiceId::REGISTRY.0));
        let source_seal = fs::read(&seal).unwrap();
        assert_eq!(source_seal, [Consistency::Crdt as u8]);
        let mut peers = vec![fixture.creator.public().to_peer_id()];
        for name in ["second", "third"] {
            let destination = fixture._scratch.0.join(name);
            let index = fixture.index(&format!("{name}-config"));
            let (entry, peer) = publish_fresh_member(
                &fixture.archive,
                fixture.seed(),
                name,
                &destination,
                &fixture.cache,
                &index,
            )
            .unwrap();
            assert_eq!(entry.id_bytes(), Some(fixture.space));
            let retained =
                super::super::read_recovery_node_key(&destination.join("node.key")).unwrap();
            assert_eq!(retained.peer_id, peer.to_string());
            assert_ne!(
                retained.bytes,
                fixture.creator.to_protobuf_encoding().unwrap()
            );
            assert_eq!(
                fs::metadata(destination.join("node.key")).unwrap().mode() & 0o777,
                0o600
            );
            assert!(!destination.join("system-agent").exists());
            assert!(!destination.join("agent-host").exists());
            assert!(!destination.join("local-agent-host").exists());
            let cid = crate::commands::space::new::read_genesis_root(
                &destination
                    .join("agents")
                    .join(format!("{:08x}.redb", ServiceId::REGISTRY.0)),
            )
            .unwrap();
            assert_eq!(common::derive_space_id(&cid), fixture.space);
            let config = local_config::load(&destination).unwrap();
            assert_eq!(
                config.local_agent_storage,
                local_config::LocalAgentStorage::Image
            );
            assert!(config.system_bootstrap_bundle.is_none());
            assert_eq!(spaces_index::load_from(&index).unwrap().spaces.len(), 1);
            assert!(!peers.contains(&peer));
            peers.push(peer);
        }
        assert_eq!(
            tree(&fixture.archive),
            source,
            "source backup bytes must stay unchanged"
        );
        assert_eq!(fs::read(&seal).unwrap(), source_seal);
        assert!(peers.len() == 3);
        assert!(super::super::verify_archive(&fixture.archive).is_ok());
        // This is first-use preparation, not source identity recovery. The
        // existing restore rule still refuses either new member's key.
        let member =
            super::super::read_recovery_node_key(&fixture._scratch.0.join("second/node.key"))
                .unwrap();
        assert!(
            super::super::require_manifest_node_identity(
                &super::super::verify_archive(&fixture.archive).unwrap(),
                &member
            )
            .is_err()
        );
    }

    #[test]
    fn seed_refuses_wrong_anchors_modified_signature_and_extra_history() {
        let fixture = Fixture::new();
        let source = tree(&fixture.archive);
        assert!(
            audit_seed(
                &fixture.archive,
                [0x73; 32],
                fixture.operator.public().to_peer_id(),
                &fixture.cache
            )
            .is_err()
        );
        let foreign = Keypair::ed25519_from_bytes([0x74; 32]).unwrap();
        assert!(
            audit_seed(
                &fixture.archive,
                fixture.space,
                foreign.public().to_peer_id(),
                &fixture.cache
            )
            .is_err()
        );
        let seed = fixture.seed();
        let path = fixture
            .data
            .join("agents")
            .join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
        let db = Arc::new(redb::Database::open(path).unwrap());
        let source_store = CrdtCommit::from_db_arc(db, [0x75; 32]).unwrap();
        let mut logs = source_store.replay_logs().unwrap();
        drop(source_store);
        let last = logs.len() - 1;
        let request = vos::node::registry_replay_request(&logs[last])
            .unwrap()
            .unwrap();
        let mut auth = request.args.get_bytes("auth").unwrap();
        *auth.last_mut().unwrap() ^= 1;
        let request = vos::value::Msg::new("add_node")
            .with("prefix", request.args.get_u32("prefix").unwrap())
            .with("peer_id", request.args.get_bytes("peer_id").unwrap())
            .with("role", NODE_ROLE_VOTER)
            .with("auth", auth);
        let mut bytes = vec![vos::value::TAG_DYNAMIC];
        use vos::Encode as _;
        bytes.extend_from_slice(&request.encode());
        logs[last].msg = bytes;
        assert!(
            validate_fresh_logs(
                &seed.nodes,
                &logs,
                fixture.space,
                &seed.root_peer,
                &seed.creator_peer
            )
            .is_err()
        );
        logs.push(logs[0].clone());
        assert!(
            validate_fresh_logs(
                &seed.nodes,
                &logs,
                fixture.space,
                &seed.root_peer,
                &seed.creator_peer
            )
            .is_err()
        );
        assert_eq!(tree(&fixture.archive), source);
        assert!(!fixture._scratch.0.join("unrequested-member").exists());
    }

    #[test]
    fn fresh_member_refuses_existing_directory_or_index_without_mutation() {
        let fixture = Fixture::new();
        let index = fixture.index("member-config");
        let destination = fixture._scratch.0.join("member");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .unwrap();
        fs::write(destination.join("keep"), b"existing owned data").unwrap();
        let before = tree(&destination);
        assert!(
            publish_fresh_member(
                &fixture.archive,
                fixture.seed(),
                "member",
                &destination,
                &fixture.cache,
                &index
            )
            .is_err()
        );
        assert_eq!(tree(&destination), before);
        assert!(!index.exists());
        let real = fixture._scratch.0.join("real-member");
        publish_fresh_member(
            &fixture.archive,
            fixture.seed(),
            "member",
            &real,
            &fixture.cache,
            &index,
        )
        .unwrap();
        let retained = tree(&real);
        let index_bytes = fs::read(&index).unwrap();
        let refused = fixture._scratch.0.join("refused-member");
        assert!(
            publish_fresh_member(
                &fixture.archive,
                fixture.seed(),
                "different-name",
                &refused,
                &fixture.cache,
                &index
            )
            .is_err()
        );
        assert!(!refused.exists());
        assert_eq!(tree(&real), retained);
        assert_eq!(fs::read(&index).unwrap(), index_bytes);
    }

    #[test]
    fn fresh_seed_envelope_refuses_retired_artifact_or_native_data() {
        let fixture = Fixture::new();
        let seed = fixture.seed();
        let mut manifest = seed.manifest.clone();
        manifest.space.registry_hash = "1".repeat(64);
        assert!(require_seed_envelope(&fixture.archive, &manifest, fixture.space).is_err());
        manifest = seed.manifest.clone();
        manifest.files.push(manifest.files[0].clone());
        manifest.files[2].path = "data/system-agent/system-agent.pins".into();
        assert!(require_seed_envelope(&fixture.archive, &manifest, fixture.space).is_err());
        fs::create_dir(fixture.data.join("system-agent")).unwrap();
        fs::write(
            fixture.data.join("system-agent/native-state"),
            b"must not migrate",
        )
        .unwrap();
        let refused = fixture._scratch.0.join("native-backup");
        let mut source_entry = seed.manifest.space;
        source_entry.data_dir = fixture.data.to_str().unwrap().into();
        let error =
            super::super::create_archive(&source_entry, &refused, &fixture.cache).unwrap_err();
        assert!(error.to_string().contains("unclassified"), "{error:#}");
        assert!(!refused.exists());
    }

    #[test]
    fn fresh_activation_and_explicit_anchor_parsing_fail_closed() {
        let scratch = Scratch::new();
        let stage = scratch.0.join("stage");
        let destination = scratch.0.join("destination");
        fs::create_dir(&stage).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(stage.join("prepared"), b"new").unwrap();
        fs::write(destination.join("retained"), b"old").unwrap();
        assert!(activate_fresh(&stage, &destination).is_err());
        assert_eq!(fs::read(destination.join("retained")).unwrap(), b"old");
        assert_eq!(fs::read(stage.join("prepared")).unwrap(), b"new");
        assert!(parse_space_id(&"0".repeat(64)).is_err());
        assert!(parse_space_id(&"A".repeat(64)).is_err());
        assert!(parse_space_id("01").is_err());
        assert_eq!(parse_space_id(&"1".repeat(64)).unwrap(), [0x11; 32]);
        let root = Keypair::ed25519_from_bytes([0x76; 32])
            .unwrap()
            .public()
            .to_peer_id();
        assert_eq!(parse_root_peer(&root.to_string()).unwrap(), root);
        assert!(parse_root_peer("not-a-peer").is_err());
    }
}
