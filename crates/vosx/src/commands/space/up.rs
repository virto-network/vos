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

    // Attach a libp2p network when the entry declares listen
    // addrs or bootnodes. Pure-local spaces (created via `space
    // new` with no `--listen`) keep network attachment off and
    // run as single-node.
    let network = build_network_if_needed(&entry, &data_dir)?;

    let mut node = match &network {
        Some(net) => VosNode::with_prefix(net.local_prefix()),
        None => VosNode::new(),
    };
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
