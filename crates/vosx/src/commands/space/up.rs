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
    pub manifest: Option<PathBuf>,
    pub listen: Vec<String>,
    pub connect: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.query)?;

    if entry.registry_hash.is_empty() {
        anyhow::bail!(
            "space '{}' has no registry_hash recorded — re-create it with \
             `vosx space new`",
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

    // Verify the genesis CrdtEvent against the advertised
    // space_id BEFORE registering the agent (which opens the
    // redb exclusively). Creators pass immediately; joiners
    // who haven't seen the genesis yet get a "trust on first
    // use" warning and proceed — on the next `space up` after
    // sync, verification activates.
    let registry_db = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
    if registry_db.exists() {
        match crate::commands::space::verify::verify_with_timeout(
            &registry_db,
            &space_id,
            std::time::Duration::from_millis(0),
        )? {
            crate::commands::space::verify::VerifyOutcome::Verified { genesis_cid } => {
                eprintln!(
                    "vosx: genesis verified (root={})",
                    hex::encode(genesis_cid),
                );
            }
            crate::commands::space::verify::VerifyOutcome::Mismatch {
                genesis_cid,
                derived,
                advertised,
            } => {
                anyhow::bail!(
                    "genesis mismatch — local registry's seq=1 root {} \
                     derives to space_id {} but the saved entry advertises {}. \
                     The bootnode pointed us at a different space, or the \
                     local data dir was tampered with.",
                    hex::encode(genesis_cid),
                    hex::encode(derived),
                    hex::encode(advertised),
                );
            }
            crate::commands::space::verify::VerifyOutcome::NoGenesisYet => {
                eprintln!(
                    "vosx: warning: registry redb has no seq=1 event yet — \
                     trust-on-first-use until sync delivers genesis. \
                     Verification activates on the next `space up`.",
                );
            }
        }
    }

    // Always attach a libp2p network — even local-only spaces
    // bind a loopback port so client commands (`space publish`,
    // `space install`, etc.) have an endpoint to dial.
    let network = build_network_for_daemon(&entry, &data_dir, &args.listen, &args.connect)?;
    let local_prefix = network.local_prefix();

    let mut node = VosNode::with_prefix(local_prefix);
    let cfg = AgentConfig::new(blob)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(replication_id)
        .persist(&data_dir);
    let id = node.register_at_id(cfg, ServiceId::REGISTRY);

    node.attach_network(network);

    eprintln!(
        "vosx: space '{}' (id={}…) registry as {id}",
        entry.name,
        &entry.id[..12],
    );

    // Reconcile the optional --manifest BEFORE we spawn the
    // currently-installed agents, so manifest-introduced
    // agents land in the same boot.
    if let Some(manifest_path) = &args.manifest {
        let (manifest, manifest_dir) =
            crate::commands::space::reconcile::parse_manifest_file(manifest_path)?;
        crate::commands::space::reconcile::reconcile(
            &node,
            &manifest,
            &manifest_dir,
            local_prefix,
        )?;
    }

    // Spawn every installed agent recorded in the registry.
    // Each gets a deterministic per-node ServiceId so its redb
    // path is stable across restarts.
    spawn_installed_agents(&mut node, &data_dir, local_prefix)?;

    // Wait for the swarm to bind, then publish endpoint info
    // so client commands (`space publish`, `space install`, …)
    // can dial us. Removed in the cleanup block at the end.
    publish_endpoint(&node, &data_dir, local_prefix)?;

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

    // Best-effort cleanup; if a crash short-circuits this,
    // the next client invocation sees the stale endpoint and
    // surfaces it via `endpoint::is_alive`.
    crate::commands::space::endpoint::delete(&data_dir);

    if panics > 0 {
        anyhow::bail!("{panics} pvm panics");
    }
    Ok(())
}

/// Build a Network for the daemon. Always attaches — local-only
/// spaces get an auto-port loopback bind so clients have an
/// endpoint to dial.
///
/// `--listen` overrides the entry's saved listen addrs entirely
/// (so the user can run multiple daemons of the same space on
/// different ports). `--connect` extends the entry's saved
/// bootnodes (additive — the user can dial extra peers
/// without losing the original).
fn build_network_for_daemon(
    entry: &spaces_index::SpaceEntry,
    data_dir: &std::path::Path,
    listen_override: &[String],
    connect_extra: &[String],
) -> anyhow::Result<vos::network::Network> {
    let parse = |s: &str, kind: &str| -> anyhow::Result<libp2p::Multiaddr> {
        libp2p::Multiaddr::from_str(s)
            .map_err(|e| anyhow::anyhow!("bad {kind} multiaddr '{s}': {e}"))
    };
    let listen_src: &[String] = if listen_override.is_empty() {
        &entry.listen
    } else {
        listen_override
    };
    let mut listen: Vec<libp2p::Multiaddr> = listen_src
        .iter()
        .map(|s| parse(s, "listen"))
        .collect::<anyhow::Result<_>>()?;
    if listen.is_empty() {
        // Default: bind to a loopback auto-port. The actual port
        // is captured into `.endpoint` once the swarm reports it.
        listen.push("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    }
    let mut bootstrap: Vec<libp2p::Multiaddr> = entry
        .bootnodes
        .iter()
        .map(|s| parse(s, "bootnode"))
        .collect::<anyhow::Result<_>>()?;
    for s in connect_extra {
        bootstrap.push(parse(s, "connect")?);
    }

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

    Ok(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap,
    }))
}

/// Wait briefly for the swarm to bind, then write the endpoint
/// descriptor so clients can find us.
fn publish_endpoint(
    node: &VosNode,
    data_dir: &std::path::Path,
    prefix: u16,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};

    let net = node
        .network()
        .ok_or_else(|| anyhow::anyhow!("network not attached when publishing endpoint"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let multiaddrs = loop {
        let addrs = net.listen_addrs();
        if !addrs.is_empty() {
            break addrs;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("swarm didn't bind a listen address within 3s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let peer_id = net.peer_id().to_string();
    let multiaddrs: Vec<String> = multiaddrs.iter().map(|m| m.to_string()).collect();
    let ep = crate::commands::space::endpoint::Endpoint {
        peer_id,
        multiaddrs: multiaddrs.clone(),
        prefix,
        pid: std::process::id(),
    };
    crate::commands::space::endpoint::write(data_dir, &ep)?;
    eprintln!("vosx: endpoint published");
    for a in &multiaddrs {
        eprintln!("  {a}");
    }
    Ok(())
}

/// Query the registry for installed agents and register each
/// on the local node. If `<data_dir>/local.toml` declares a
/// `subscriptions` filter, only listed instances spawn — the
/// rest are skipped (their state still arrives via gossipsub
/// for full replicas, but isn't materialized into a running
/// agent here).
fn spawn_installed_agents(
    node: &mut VosNode,
    data_dir: &std::path::Path,
    local_prefix: u16,
) -> anyhow::Result<()> {
    use space_registry::SpaceRegistryRef;

    let local_cfg = crate::commands::space::subscriptions::load(data_dir)
        .unwrap_or_default();
    if local_cfg.is_filtering() {
        eprintln!(
            "vosx: subscriptions filter active — {} agent(s)",
            local_cfg.subscriptions.len(),
        );
    }

    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let agents = vos::block_on(reg.agents(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    for a in agents {
        if !local_cfg.should_spawn(&a.instance_name) {
            eprintln!(
                "vosx:   skipping '{}' (not subscribed)",
                a.instance_name,
            );
            continue;
        }
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

        // on_start payloads (from manifest reconciliation) get
        // dispatched on cold start. Stored as rkyv-encoded
        // `Vec<Vec<u8>>` on the agent row.
        if !a.install_payloads.is_empty() {
            let mut av = vos::rkyv::util::AlignedVec::<16>::with_capacity(a.install_payloads.len());
            av.extend_from_slice(&a.install_payloads);
            let archived = unsafe {
                vos::rkyv::access_unchecked::<<Vec<Vec<u8>> as vos::rkyv::Archive>::Archived>(&av)
            };
            match vos::rkyv::deserialize::<Vec<Vec<u8>>, vos::rkyv::rancor::Error>(archived) {
                Ok(payloads) if !payloads.is_empty() => {
                    cfg = cfg.with_init_payloads(payloads);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "vosx: agent '{}' has unparseable install_payloads, ignoring: {e}",
                        a.instance_name,
                    );
                }
            }
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
///
/// Public so `DaemonClient::resolve_target` can compute the
/// same value when resolving an instance name to a ServiceId
/// for `space call`.
pub fn derive_instance_svc_id(instance_name: &str, local_prefix: u16) -> u32 {
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
