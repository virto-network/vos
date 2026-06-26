//! `space new` — scaffold a fresh space.
//!
//! Boots the registry actor in a temp data dir, sends an
//! `add_node` for the creator (the first entry in the
//! members table), reads the genesis DAG root from the
//! resulting redb, derives `space_id =
//! derive_space_id(genesis_dag_root)`, then renames the temp
//! dir to `~/.local/share/vosx/<space_id>/`. The first commit
//! IS the genesis — joiners syncing this space see the same
//! root and can verify the advertised space_id matches.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use space_registry::{AUTH_ROLE_ADMIN, NODE_ROLE_VOTER, STATUS_OK, SpaceRegistryRef};
use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};

use crate::blob_store::{self, BlobSource};
use crate::commands::space::op_sign::op_auth;
use crate::output;
use crate::paths;
use crate::spaces_index::{self, SpacesIndex};

#[derive(Serialize)]
struct CreatedView<'a> {
    name: &'a str,
    space_id: String,
    genesis_root: String,
    data_dir: String,
    node_key: String,
    registry_hash: String,
    registry_source: &'a str,
    peer_id: String,
}

pub struct Args {
    pub name: String,
    pub registry: Option<String>,
    pub data_dir: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    if args.name.is_empty() {
        anyhow::bail!("--name is required and must be non-empty");
    }

    // 1. Resolve and cache the registry blob — explicit
    //    --registry first, bundled fallback otherwise.
    let (registry_hash, registry_bytes, registry_label) =
        resolve_registry_source(args.registry.as_deref())?;
    let registry_blob = grey_transpiler::link_elf(&registry_bytes)
        .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;

    // 2. Generate a per-space libp2p keypair + derive prefix.
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer_id);

    // 3. Boot the registry in a temp dir under `data_root` so
    //    the eventual rename to the canonical space dir stays
    //    within the same filesystem. The guard wipes the dir
    //    on any early-return / panic so genesis aborts don't
    //    litter `data_root` with `.genesis-*` skeletons.
    let temp_dir = paths::data_root().join(format!(
        ".genesis-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::create_dir_all(temp_dir.join("agents"))?;
    let mut temp_guard = TempDirGuard(Some(temp_dir.clone()));

    // 4. Register the registry agent. The replication_id passed
    //    here doesn't affect the on-disk layout — it's a
    //    network-only concern (gossipsub topic) that's not
    //    engaged for this offline boot. The space_id-derived
    //    replication_id will be used on subsequent `space up`.
    let mut node = VosNode::with_prefix(local_prefix);
    let cfg = AgentConfig::new(registry_blob)
        .with_consistency(Consistency::Crdt)
        .with_replication_id([0u8; 32])
        .persist(&temp_dir);
    let _id = node.register_at_id(cfg, ServiceId::REGISTRY);

    // 5. Genesis commits: anchor the operator's CLI identity as
    //    the signing root, grant it ADMIN, and enrol the node as the
    //    first voter. All three ride the genesis DAG, so they're pinned
    //    into `space_id` — a joiner verifies the root the same way it
    //    verifies the space id, and from then on every gated registry
    //    mutation must be signed by the root or an admin it delegated
    //    to. The operator key signs the two gated ops; `set_root` is
    //    the unsigned anchor (first-write-wins, refused thereafter).
    let operator_kp = crate::identity::load_or_create()?;
    let operator_peer_id = libp2p::PeerId::from(operator_kp.public()).to_bytes();
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);

    let status = vos::block_on(reg.set_root(&mut &node, operator_peer_id.clone()))
        .map_err(|e| anyhow::anyhow!("genesis set_root failed: {e}"))?;
    if status != STATUS_OK {
        anyhow::bail!("genesis set_root returned status {status}");
    }

    let grant_auth = op_auth(
        &operator_kp,
        "grant_role",
        &[&operator_peer_id, &[AUTH_ROLE_ADMIN]],
    )?;
    let status = vos::block_on(reg.grant_role(
        &mut &node,
        operator_peer_id.clone(),
        AUTH_ROLE_ADMIN,
        grant_auth,
    ))
    .map_err(|e| anyhow::anyhow!("genesis grant_role failed: {e}"))?;
    if status != STATUS_OK {
        anyhow::bail!("genesis grant_role returned status {status}");
    }

    let node_peer_id = peer_id.to_bytes();
    let node_auth = op_auth(
        &operator_kp,
        "add_node",
        &[
            &(local_prefix as u32).to_le_bytes(),
            &node_peer_id,
            &[NODE_ROLE_VOTER],
        ],
    )?;
    let status = vos::block_on(reg.add_node(
        &mut &node,
        local_prefix as u32,
        node_peer_id,
        NODE_ROLE_VOTER,
        node_auth,
    ))
    .map_err(|e| anyhow::anyhow!("genesis add_node failed: {e}"))?;
    if status != STATUS_OK {
        anyhow::bail!("genesis add_node returned status {status}");
    }

    // 6. Drain the runtime so the commit is fully flushed.
    node.shutdown();
    let results = node.collect();
    for r in &results {
        if let Some(err) = &r.error {
            anyhow::bail!("genesis registry boot: {err}");
        }
    }

    // 7. Read the genesis DAG root from the registry's redb.
    let registry_db = temp_dir
        .join("agents")
        .join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
    let genesis_root = read_genesis_root(&registry_db)?;
    let space_id = crate::commands::space::common::derive_space_id(&genesis_root);

    // 8. Move temp dir to the canonical location. Disarm the
    //    guard once the rename succeeds — the destination dir
    //    is now legitimate state, not a temp leftover.
    let final_dir = args.data_dir.unwrap_or_else(|| paths::space_dir(&space_id));
    if final_dir.exists() {
        anyhow::bail!("space data dir already exists: {}", final_dir.display(),);
    }
    if let Some(parent) = final_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&temp_dir, &final_dir).map_err(|e| {
        anyhow::anyhow!(
            "rename {} → {}: {e}",
            temp_dir.display(),
            final_dir.display()
        )
    })?;
    temp_guard.disarm();

    // 9. Persist the keypair under the final dir.
    let key_path = final_dir.join("node.key");
    let key_bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("encode keypair: {e}"))?;
    std::fs::write(&key_path, key_bytes)?;

    // 10. Append to the spaces index.
    let mut index = spaces_index::load().unwrap_or_else(|_| SpacesIndex::default());
    let mut entry = spaces_index::entry_for(&space_id, &args.name);
    entry.data_dir = final_dir.to_string_lossy().to_string();
    entry.registry_hash = registry_hash.to_hex();
    spaces_index::upsert(&mut index, entry);
    spaces_index::save(&index)?;

    // 11. Print.
    let space_id_hex = paths::space_id_hex(&space_id);
    if output::is_json() {
        output::print_json(&CreatedView {
            name: &args.name,
            space_id: space_id_hex,
            genesis_root: hex::encode(genesis_root),
            data_dir: final_dir.to_string_lossy().to_string(),
            node_key: key_path.to_string_lossy().to_string(),
            registry_hash: registry_hash.to_hex(),
            registry_source: &registry_label,
            peer_id: peer_id.to_string(),
        });
    } else {
        println!("created space '{}'", args.name);
        println!("  space_id     = {space_id_hex}");
        println!("  genesis_root = {}", hex::encode(genesis_root));
        println!("  data_dir     = {}", final_dir.display());
        println!("  node.key     = {}", key_path.display());
        println!("  registry     = {registry_label} ({registry_hash})");
        println!("  peer_id      = {peer_id}");
        println!();
        println!("next: `vosx space up {} [--listen <multiaddr>]`", args.name);
        println!("the bootnode hint <space_id>@<multiaddr>/p2p/<peer_id> is");
        println!(
            "printed by `space info {}` once the daemon's running.",
            args.name
        );
    }

    Ok(())
}

/// Resolve the registry source: explicit `--registry` if given,
/// else the bundled blob baked in at `vosx` build time.
/// Returns `(hash, bytes, display_label)` so the print step
/// can show whatever the user asked for (or "(bundled)").
pub fn resolve_registry_source(
    registry: Option<&str>,
) -> anyhow::Result<(blob_store::BlobHash, Vec<u8>, String)> {
    if let Some(s) = registry {
        let source = BlobSource::parse(s);
        let (hash, bytes) =
            blob_store::resolve(&source).map_err(|e| anyhow::anyhow!("registry blob: {e}"))?;
        return Ok((hash, bytes, s.to_string()));
    }
    match crate::bundled::registry_elf() {
        Some(bytes) => {
            let hash = blob_store::cache_put(bytes)
                .map_err(|e| anyhow::anyhow!("cache bundled blob: {e}"))?;
            Ok((hash, bytes.to_vec(), "(bundled)".to_string()))
        }
        None => anyhow::bail!(
            "no --registry provided and no bundled blob — run \
             `cd crates/actors/space-registry && cargo actor` and \
             rebuild vosx, or pass --registry <source>"
        ),
    }
}

/// RAII cleanup for the genesis temp dir. Wipes the directory
/// on Drop unless `disarm()` was called first — covers every
/// `?` short-circuit, every `bail!`, and a panic from the
/// runtime / blob resolution. After the rename to the
/// canonical space dir succeeds, callers disarm so the now-
/// legitimate state survives.
struct TempDirGuard(Option<PathBuf>);

impl TempDirGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_dir_all(&p);
        }
    }
}

/// Open the registry's redb and return the CID of the `seq == 0`
/// commit — the genesis anchor `space_id` derives from.
///
/// Genesis is now several commits (`set_root`, the operator's ADMIN
/// grant, the first `add_node`); the `seq == 0` event is `set_root`,
/// so `space_id` binds to the root identity. This MUST key on
/// `seq == 0` (not the DAG tip): `space up` and joiners verify the
/// space via the same `seq == 0` scan in `verify.rs`, and the tip
/// moves with every post-genesis commit.
fn read_genesis_root(db_path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    use redb::ReadableTable;
    const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");

    let db = redb::Database::open(db_path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", db_path.display()))?;
    let txn = db
        .begin_read()
        .map_err(|e| anyhow::anyhow!("begin read: {e}"))?;
    let table = txn
        .open_table(DAG_TABLE)
        .map_err(|e| anyhow::anyhow!("open dag table: {e}"))?;

    for row in table.iter().map_err(|e| anyhow::anyhow!("iter dag: {e}"))? {
        let (key, value) = row.map_err(|e| anyhow::anyhow!("read dag row: {e}"))?;
        let bytes: &[u8] = value.value();
        // DagNode wire: [payload_len:u64 LE][payload][n_children:u64 LE][children…]
        if bytes.len() < 8 {
            continue;
        }
        let payload_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        if bytes.len() < 8 + payload_len {
            continue;
        }
        let Some(event) = vos::effect_log::CrdtEvent::from_bytes(&bytes[8..8 + payload_len]) else {
            continue;
        };
        if event.seq != 0 {
            continue;
        }
        let key_bytes: &[u8] = key.value();
        if key_bytes.len() == 32 {
            let mut cid = [0u8; 32];
            cid.copy_from_slice(key_bytes);
            return Ok(cid);
        }
    }
    anyhow::bail!("registry has no seq==0 commit after genesis")
}
