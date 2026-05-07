//! `space up` — boot a saved space and run forever.
//!
//! Loads the registry blob from the local cache (looked up by
//! the hash recorded in spaces.toml at `space new` time),
//! registers it as the well-known `ServiceId::REGISTRY` agent
//! with `Consistency::Crdt`, and hands the node off to
//! `run_forever` (or `run` for `--once`).

use std::path::PathBuf;
use std::str::FromStr;

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};

use crate::blob_store::{self, BlobHash};
use crate::space_lock::SpaceLock;
use crate::spaces_index;

pub struct Args {
    pub query: String,
    pub once: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.query)?;

    if entry.registry_hash.is_empty() {
        anyhow::bail!(
            "space '{}' has no registry_hash recorded — re-create it \
             with `vosx space new` (Phase 1a entries before the registry-hash \
             field landed lack this metadata)",
            entry.name,
        );
    }
    let hash = BlobHash::from_hex(&entry.registry_hash)
        .map_err(|_| anyhow::anyhow!("space registry_hash is not 64 hex chars"))?;
    let elf = match blob_store::cache_get(&hash)? {
        Some(b) => b,
        None => anyhow::bail!(
            "registry blob {} not in local cache. Re-fetch with \
             `vosx space pull-blob {}` once that command lands.",
            hash, hash,
        ),
    };
    // Cache stores raw ELF bytes (hash addresses the source); the
    // PVM kernel needs the transpiled JAR blob.
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;

    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
    let replication_id = derive_registry_replication_id(&space_id);

    let data_dir = PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!(
            "data dir does not exist: {} (was the space deleted?)",
            data_dir.display(),
        );
    }

    // Hold the per-space lock for the lifetime of this command.
    // Concurrent `space publish`/`install`/etc. will see the
    // flock and error rather than corrupt the redb.
    let _lock = SpaceLock::acquire(&data_dir)?;

    // Attach a libp2p network when the entry declares listen
    // addrs or bootnodes. Pure-local spaces (created via `space
    // new` with no `--listen`) keep network attachment off and
    // run as single-node.
    let network = build_network_if_needed(&entry, &data_dir)?;
    let local_prefix = network.as_ref().map(|n| n.local_prefix()).unwrap_or(0);

    let mut node = VosNode::with_prefix(local_prefix);
    let cfg = AgentConfig::new(blob)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(replication_id)
        .persist(&data_dir);
    let id = node.register_at_id(cfg, ServiceId::REGISTRY);

    if let Some(net) = network {
        node.attach_network(net);
    }

    eprintln!(
        "vosx: space '{}' (id={}…) registry as {id}",
        entry.name,
        &entry.id[..12],
    );

    // Spawn every installed agent recorded in the registry.
    // Each gets a deterministic per-node ServiceId so its redb
    // path is stable across restarts.
    spawn_installed_agents(&mut node, &data_dir, local_prefix)?;

    if args.once {
        eprintln!("vosx: --once — exiting once registry goes idle");
        node.run();
    } else {
        eprintln!("vosx: running until shutdown (Ctrl-C)");
        node.run_forever();
    }

    let results = node.collect();
    let mut panics = 0u32;
    for r in &results {
        panics += r.panics;
        if let Some(err) = &r.error {
            eprintln!("vosx: agent {} error: {err}", r.id);
        }
    }
    if panics > 0 {
        anyhow::bail!("{panics} pvm panics");
    }
    Ok(())
}

/// Build a libp2p network from the entry's listen + bootnodes
/// fields when at least one is non-empty. Loads the per-space
/// keypair from `data_dir/node.key`. Returns `None` for
/// pure-local spaces.
fn build_network_if_needed(
    entry: &spaces_index::SpaceEntry,
    data_dir: &std::path::Path,
) -> anyhow::Result<Option<vos::network::Network>> {
    if entry.listen.is_empty() && entry.bootnodes.is_empty() {
        return Ok(None);
    }
    let parse = |s: &str, kind: &str| -> anyhow::Result<libp2p::Multiaddr> {
        libp2p::Multiaddr::from_str(s)
            .map_err(|e| anyhow::anyhow!("bad {kind} multiaddr '{s}': {e}"))
    };
    let listen: Vec<libp2p::Multiaddr> = entry
        .listen
        .iter()
        .map(|s| parse(s, "listen"))
        .collect::<anyhow::Result<_>>()?;
    let bootstrap: Vec<libp2p::Multiaddr> = entry
        .bootnodes
        .iter()
        .map(|s| parse(s, "bootnode"))
        .collect::<anyhow::Result<_>>()?;

    let key_path = data_dir.join("node.key");
    let key_bytes = std::fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", key_path.display()))?;
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode keypair: {e}"))?;
    let peer_id = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer_id);
    eprintln!(
        "vosx: node identity {peer_id} (prefix {local_prefix:#06x})",
    );

    Ok(Some(vos::network::Network::start(
        vos::network::NetworkConfig {
            keypair,
            local_prefix,
            listen,
            bootstrap,
        },
    )))
}

/// Query the registry for installed agents and register each
/// on the local node.
fn spawn_installed_agents(
    node: &mut VosNode,
    data_dir: &std::path::Path,
    local_prefix: u16,
) -> anyhow::Result<()> {
    use space_registry::SpaceRegistryRef;

    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let agents = vos::block_on(reg.agents(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    for a in agents {
        let program_hash = BlobHash(a.program_hash);
        let elf = match blob_store::cache_get(&program_hash)? {
            Some(b) => b,
            None => {
                eprintln!(
                    "vosx: skipping agent '{}' — program blob {program_hash} not in local cache",
                    a.instance_name,
                );
                continue;
            }
        };
        let blob = grey_transpiler::link_elf(&elf)
            .map_err(|e| anyhow::anyhow!("transpile {}: {e:?}", a.instance_name))?;

        let consistency = match a.consistency {
            0 => Consistency::Ephemeral,
            1 => Consistency::Local,
            2 => Consistency::Crdt,
            3 => Consistency::Raft,
            other => {
                eprintln!(
                    "vosx: skipping agent '{}' — unknown consistency {other}",
                    a.instance_name,
                );
                continue;
            }
        };

        let mut cfg = AgentConfig::new(blob).with_consistency(consistency);
        if matches!(consistency, Consistency::Local | Consistency::Crdt | Consistency::Raft) {
            cfg = cfg.persist(data_dir);
        }
        if matches!(consistency, Consistency::Crdt | Consistency::Raft) {
            cfg = cfg.with_replication_id(a.replication_id);
        }
        if !a.install_args.is_empty() {
            cfg = cfg.with_storage(vec![(
                vos::lifecycle::INIT_KEY.to_vec(),
                a.install_args.clone(),
            )]);
        }

        let svc_id = vos::abi::service::ServiceId(derive_instance_svc_id(
            &a.instance_name,
            local_prefix,
        ));
        let id = node.register_at_id(cfg, svc_id);
        eprintln!(
            "vosx:   agent '{}' as {id} ({})",
            a.instance_name,
            space_registry::consistency_name(a.consistency),
        );
    }
    Ok(())
}

/// Deterministic per-node ServiceId for an installed agent.
/// `local_prefix` is the node's 16-bit identity prefix; the
/// low 16 bits are derived from `instance_name` and clamped to
/// `[0x100, 0x7FFF]` so it can't collide with `ServiceId::REGISTRY`
/// (= 0) or any reserved low system ids. Stable across restarts
/// of the same node so each instance's redb path persists.
fn derive_instance_svc_id(instance_name: &str, local_prefix: u16) -> u32 {
    let mut h = blake2b_simd::Params::new().hash_length(2).to_state();
    h.update(b"vos-instance-svc-id/v1");
    h.update(&[0u8]);
    h.update(instance_name.as_bytes());
    let bytes = h.finalize();
    let buf = bytes.as_bytes();
    let raw = u16::from_le_bytes([buf[0], buf[1]]);
    let local = (raw & 0x7FFF).max(0x100);
    ((local_prefix as u32) << 16) | (local as u32)
}

/// Per-space registry replication-id: blake2b("vos-space-registry/v1"
/// || space_id). Deterministic from space_id so any two replicas
/// of the same space subscribe to the same gossipsub topic.
pub fn derive_registry_replication_id(space_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-space-registry/v1");
    h.update(&[0u8]);
    h.update(space_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}
