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
use crate::commands::space::common::{
    consistency_from_u8, derive_hyperspace_id, instance_service_id, registry_replication_id,
};
use crate::commands::space::payload_codec;
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
            "registry blob {hash} not in local cache. Re-fetch with \
             `vosx space pull-blob {hash}` once that command lands.",
        ),
    };
    // Cache stores raw ELF bytes (hash addresses the source); the
    // PVM kernel needs the transpiled JAR blob.
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;

    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
    let replication_id = registry_replication_id(&space_id);

    let data_dir = PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!(
            "data dir does not exist: {} (was the space forgotten?)",
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
                tracing::info!("genesis verified (root={})", hex::encode(genesis_cid));
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
                tracing::warn!(
                    "registry redb has no seq=1 event yet — trust-on-first-use \
                     until sync delivers genesis; verification activates on the \
                     next `space up`",
                );
            }
        }
    }

    // Pre-parse the manifest (if any) so we know whether to spawn
    // the hyperspace registry alongside the local one. The manifest
    // gets reconciled below — we only peek at it here.
    let parsed_manifest = args
        .manifest
        .as_ref()
        .map(|p| crate::commands::space::reconcile::parse_manifest_file(p))
        .transpose()?;
    let manifest_hyperspace = parsed_manifest
        .as_ref()
        .and_then(|(m, _)| m.hyperspace.clone());
    // Effective membership: a manifest value wins (and is persisted
    // below); otherwise fall back to what the index remembers, so a
    // bare `space up` — a restart without --manifest — re-attaches the
    // space to its federation instead of silently detaching it.
    let persisted_hyperspace = (!entry.hyperspace.is_empty()).then(|| entry.hyperspace.clone());
    let hyperspace = manifest_hyperspace.clone().or(persisted_hyperspace);

    // First `space up --manifest` (or a manifest that changes the name)
    // records the hyperspace in the spaces index so subsequent boots
    // re-attach without needing the manifest again.
    if let Some(name) = &manifest_hyperspace
        && entry.hyperspace != *name
    {
        let mut updated = entry.clone();
        updated.hyperspace = name.clone();
        let mut idx = spaces_index::load()?;
        spaces_index::upsert(&mut idx, updated);
        spaces_index::save(&idx)?;
        tracing::info!("persisted hyperspace '{name}' for space '{}'", entry.name);
    }

    // Agents that declared `device_secret = true` — they get a node-local
    // secret seed provisioned post-spawn (see `provision_device_seeds`).
    // Captured here before the manifest is consumed by the reconcile block.
    // Node-local by design: the flag never rides the replicated AgentRow.
    let device_secret_agents: Vec<String> = parsed_manifest
        .as_ref()
        .map(|(m, _)| {
            m.agents
                .iter()
                .filter(|a| a.device_secret)
                .map(|a| a.name.clone())
                .collect()
        })
        .unwrap_or_default();

    // Node-local per-agent policy from the manifest (`tick_ms` + `intra_caps`)
    // — never replicated. Applied at spawn in `agent_config_from_row`. Malformed
    // intra_caps fail the boot eagerly (like the extension path).
    let agent_policies = collect_agent_policies(parsed_manifest.as_ref().map(|(m, _)| m))?;

    // Always attach a libp2p network — even local-only spaces
    // bind a loopback port so client commands (`space publish`,
    // `space install`, etc.) have an endpoint to dial.
    let network = build_network_for_daemon(entry, &data_dir, &args.listen, &args.connect)?;
    let local_prefix = network.local_prefix();

    let mut node = VosNode::with_prefix(local_prefix);

    // Record this daemon's operator — the CLI identity that ran `vosx space
    // up` (the same `vosx/identity.key` the operator later presents when
    // driving agents with `vosx <agent> …`). Two roles: (1) the locality
    // gate admits this caller, and only this caller, to a device-local
    // (`consistency = local`) agent such as the messenger, so the operator
    // can drive their own E2EE messenger while every remote peer is refused;
    // (2) the registry agent author-signs catalog mutators on relay with
    // this key — a keyless PVM agent (the messenger cloning a channel's
    // actor pair) or the in-process reconcile can't carry a CLI signature,
    // so the daemon signs `install`/`publish`/… before recording. Set BEFORE
    // registering the registry so its thread captures the signer. A
    // best-effort load: if the operator identity can't be resolved the
    // daemon still boots, but no caller reaches a confined agent and no
    // catalog op is signed (fail closed).
    match crate::identity::load_or_create() {
        Ok(kp) => {
            let operator = libp2p::PeerId::from(kp.public());
            let operator_bytes = operator.to_bytes();
            node.set_operator_peer(operator_bytes.clone());
            node.set_operator_signer(move |canonical: &[u8]| {
                // libp2p ed25519 sign interops with the registry's
                // ed25519-dalek verify_strict; pack as signer_peer_id || sig(64).
                let sig = kp.sign(canonical).ok()?;
                let sig: [u8; 64] = sig.as_slice().try_into().ok()?;
                Some(vos::registry::pack_auth(&operator_bytes, &sig))
            });
            tracing::info!(%operator, "auth: recorded operator for device-local agents");
        }
        Err(e) => {
            tracing::warn!(
                "auth: could not load operator identity ({e}); device-local agents will be \
                 unreachable AND this node cannot author registry catalog ops \
                 (install/publish/upgrade/…) — if this is the space-admin node its manifest \
                 agents will not install. Restart with a readable identity matching the space root.",
            );
        }
    }

    // Bind the registry's genesis to this space so a member can't grind a
    // low-CID forged `set_root` and hijack the registry root on replay
    // (the hyperspace registry is the separate-trust federation surface
    // and is left ungated). See `genesis_node_validator`.
    let cfg = AgentConfig::new(blob.clone())
        .with_consistency(Consistency::Crdt)
        .with_replication_id(replication_id)
        .with_node_validator(crate::commands::space::common::genesis_node_validator(space_id))
        .persist(&data_dir);
    let id = node.register_at_id(cfg, ServiceId::REGISTRY);

    // Spawn the hyperspace registry replica if this space declares
    // membership in one. Same blob as the local registry; distinct
    // ServiceId slot (HYPERSPACE_REGISTRY = svc_id 1) and a
    // replication_id derived from the hyperspace name so all member
    // spaces' nodes converge on a single shared registry. The slot
    // id is well-known so callers don't need the return value.
    if let Some(name) = &hyperspace {
        let hs_rep = derive_hyperspace_id(name);
        let hs_cfg = AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .with_replication_id(hs_rep)
            .persist(&data_dir);
        let hs_id = node.register_at_id(hs_cfg, ServiceId::HYPERSPACE_REGISTRY);
        tracing::info!(
            "hyperspace '{name}' registry as {hs_id} (rep={}…)",
            &hex::encode(hs_rep)[..12],
        );
    }

    node.attach_network(network);

    tracing::info!(
        "space '{}' (id={}…) registry as {id}{}",
        entry.name,
        &entry.id[..12],
        hyperspace
            .as_ref()
            .map(|n| format!(" — hyperspace '{n}'"))
            .unwrap_or_default(),
    );

    // Reconcile the optional --manifest BEFORE we spawn the
    // currently-installed agents, so manifest-introduced
    // agents land in the same boot. Reconcile returns each
    // extension's effective relay caps, which we stamp into the
    // local endpoint descriptor below so `space describe` /
    // `space caps` can surface them.
    let mut extension_caps = Vec::new();
    if let Some((manifest, manifest_dir)) = parsed_manifest {
        extension_caps = crate::commands::space::reconcile::reconcile(
            &mut node,
            &manifest,
            &manifest_dir,
            local_prefix,
            &space_id,
        )?;
    }

    // Spawn every installed agent recorded in the registry.
    // Each gets a deterministic per-node ServiceId so its redb
    // path is stable across restarts.
    spawn_installed_agents(
        &mut node,
        &data_dir,
        local_prefix,
        hyperspace.is_some(),
        &agent_policies,
    )?;

    // Provision device-local secret seeds for agents that declared
    // `device_secret = true` (the messenger's MLS CSPRNG root). Runs after
    // spawn so the targets are live; the seed never touches the replicated
    // registry — it lives only in a node-local sidecar. Idempotent.
    provision_device_seeds(&node, &device_secret_agents, &data_dir, local_prefix);

    // The space creator's operator key is granted ADMIN at genesis
    // (a signed `grant_role` baked into the DAG by `space new`),
    // so there's no first-boot bootstrap file to consume here.

    // Wait for the swarm to bind, then publish endpoint info
    // so client commands (`space publish`, `space install`, …)
    // can dial us. Removed in the cleanup block at the end.
    publish_endpoint(&node, &data_dir, local_prefix, extension_caps)?;

    if args.once {
        tracing::info!("--once: exiting when registry goes idle");
        node.run();
    } else {
        // Install SIGINT/SIGTERM handlers so the daemon exits
        // cleanly on `docker stop` / `kill -TERM` / Ctrl-C
        // without losing in-flight commits or leaking the
        // endpoint file. The handler flips the same
        // AtomicBool that `run_forever`'s poll loop watches.
        crate::shutdown::install(node.shutdown_handle());
        tracing::info!("running until shutdown (Ctrl-C / SIGTERM)");

        // Spawn-reconcile from the router tick hook: agents
        // installed after boot — `space install`, `dev new`, an
        // extension calling `registry.install`, or rows CRDT-synced
        // from a peer — come up within a few seconds instead of
        // waiting for the next daemon restart. The subscriptions
        // filter is captured once here; editing local.toml still
        // needs a restart to take effect.
        let local_cfg = crate::commands::space::subscriptions::load(&data_dir).unwrap_or_default();
        let has_hyperspace = hyperspace.is_some();
        let mut damped = std::collections::HashSet::new();
        let mut boot_grace = BootGrace::new();
        let mut query_warned = false;
        let mut last_pass = std::time::Instant::now();
        // chronos clock/randomness feed (`vos::chronos_feed::ChronosFeeder`): a
        // separate, faster keepalive gate than the spawn-reconcile pass. The
        // per-space domain is the space id; the feeder holds its own cross-pass
        // state and the node's static VRF keypair. A node.key read failure
        // disables the feed rather than the whole daemon.
        let mut chronos_feeder =
            match vos::chronos_feed::ChronosFeeder::new(&data_dir, entry.id.as_bytes().to_vec()) {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!("chronos feed disabled: {e}");
                    None
                }
            };
        let mut last_feed = std::time::Instant::now();
        node.run_forever_with(|n| {
            if last_feed.elapsed() >= CHRONOS_FEED_EVERY {
                last_feed = std::time::Instant::now();
                if let Some(feeder) = chronos_feeder.as_mut() {
                    feeder.feed(n, local_prefix);
                }
            }
            if last_pass.elapsed() < SPAWN_RECONCILE_EVERY {
                return;
            }
            last_pass = std::time::Instant::now();
            match reconcile_installed_agents(
                n,
                &data_dir,
                local_prefix,
                has_hyperspace,
                &local_cfg,
                &mut damped,
                &mut boot_grace,
                &agent_policies,
            ) {
                Ok(()) => query_warned = false,
                // Usually a stopped/wedged registry; the condition
                // persists across passes, so warn once and demote
                // the 2s-cadence repeats.
                Err(e) if !query_warned => {
                    query_warned = true;
                    tracing::warn!("spawn-reconcile: {e}");
                }
                Err(e) => tracing::debug!("spawn-reconcile: {e}"),
            }
        });
    }

    let results = node.collect();
    let mut panics = 0u32;
    for r in &results {
        panics += r.panics;
        if let Some(err) = &r.error {
            tracing::error!("agent {} error: {err}", r.id);
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
/// Listen-addr resolution order (first non-empty wins):
///   1. `--listen` flag(s) on this `space up` invocation
///   2. `local.toml`'s `listen = [...]` (per-space user pref)
///   3. default `/ip4/127.0.0.1/tcp/0` (loopback auto-port)
///
/// `--connect` extends the entry's saved bootnodes additively
/// — the user can dial extra peers without losing the
/// original join target.
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
    let local_cfg = crate::commands::space::subscriptions::load(data_dir).unwrap_or_default();
    let listen_src: &[String] = if !listen_override.is_empty() {
        listen_override
    } else if !local_cfg.listen.is_empty() {
        &local_cfg.listen
    } else {
        &[]
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
    tracing::info!("node identity {peer_id} (prefix {local_prefix:#06x})");

    // mDNS auto-dial is on by default — a long-running daemon
    // benefits from same-LAN peer discovery. Set
    // `VOSX_DISABLE_MDNS=1` to opt out; the integration suite uses
    // it so test daemons don't latch onto unrelated libp2p apps
    // (IPFS / Substrate / etc.) on the dev machine.
    let auto_dial_mdns = std::env::var("VOSX_DISABLE_MDNS").is_err();
    Ok(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap,
        auto_dial_mdns,
    }))
}


/// Node-local per-agent policy from the manifest (never replicated): the
/// periodic `tick_ms` and the parsed `intra_caps` relay bound.
#[derive(Default, Clone)]
struct AgentLocalPolicy {
    tick_ms: Option<u64>,
    intra_caps: Vec<vos::IntraCap>,
}

type AgentPolicies = std::collections::BTreeMap<String, AgentLocalPolicy>;

/// Collect the `tick_ms` / `intra_caps` policy for each manifest agent. Parses
/// the `intra_caps` strings eagerly so a malformed cap fails the boot.
fn collect_agent_policies(
    manifest: Option<&crate::commands::space::reconcile::Manifest>,
) -> anyhow::Result<AgentPolicies> {
    let mut map = AgentPolicies::new();
    let Some(m) = manifest else {
        return Ok(map);
    };
    for a in &m.agents {
        let mut intra_caps = Vec::with_capacity(a.intra_caps.len());
        for tok in &a.intra_caps {
            intra_caps.push(
                vos::IntraCap::parse(tok)
                    .map_err(|e| anyhow::anyhow!("agent '{}': intra_cap '{tok}': {e}", a.name))?,
            );
        }
        let tick_ms = a.tick_ms.filter(|ms| *ms > 0);
        if tick_ms.is_some() || !intra_caps.is_empty() {
            map.insert(
                a.name.clone(),
                AgentLocalPolicy {
                    tick_ms,
                    intra_caps,
                },
            );
        }
    }
    Ok(map)
}

/// Provision each `device_secret = true` agent with a node-local CSPRNG seed
/// (the messenger's MLS confidentiality root). The seed is 32 bytes of OS
/// entropy held in a `{data_dir}/agents/{svc_id:08x}.seed` sidecar — node-local
/// like the P0 `.seal`, never replicated — and delivered by a `seed` message
/// over a local `Caller::System` invoke (a node-local, host-initiated path
/// that bypasses the auth gate). Idempotent: the agent persists the seed in
/// its Local redb, so a re-send on a later boot is a no-op. Best-effort — a
/// failure to seed is logged, not fatal.
fn provision_device_seeds(node: &VosNode, agents: &[String], data_dir: &std::path::Path, daemon_prefix: u16) {
    for name in agents {
        let svc_id = crate::commands::space::common::instance_service_id(name, daemon_prefix);
        let seed = match load_or_mint_device_seed(data_dir, svc_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(agent = %name, "device seed: {e}");
                continue;
            }
        };
        let msg = vos::value::Msg::new("seed").with("seed_bytes", seed);
        let encoded = vos::Encode::encode(&msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        match node.invoke_with_timeout(svc_id, payload, std::time::Duration::from_secs(5)) {
            Some(_) => tracing::info!(agent = %name, "device seed provisioned"),
            None => tracing::warn!(
                agent = %name,
                "device seed: provisioning invoke returned no reply (agent not spawned?)"
            ),
        }
    }
}

/// Load an agent's 32-byte device seed from its node-local sidecar, minting
/// fresh OS entropy (persisted `0600`) on first boot.
fn load_or_mint_device_seed(data_dir: &std::path::Path, svc_id: ServiceId) -> anyhow::Result<Vec<u8>> {
    let dir = data_dir.join("agents");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{:08x}.seed", svc_id.0));
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
        tracing::warn!(?path, "device seed sidecar has wrong length; re-minting");
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("OS entropy for device seed: {e}"))?;
    write_secret_file(&path, &seed)?;
    Ok(seed.to_vec())
}

/// Write a secret file, `0600` on Unix.
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)?;
    Ok(())
}

fn publish_endpoint(
    node: &VosNode,
    data_dir: &std::path::Path,
    prefix: u16,
    extensions: Vec<crate::commands::space::endpoint::ExtensionCaps>,
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
        extensions,
    };
    crate::commands::space::endpoint::write(data_dir, &ep)?;
    tracing::info!("endpoint published on {} address(es)", multiaddrs.len());
    for a in &multiaddrs {
        tracing::info!("  {a}");
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
    has_hyperspace: bool,
    policies: &AgentPolicies,
) -> anyhow::Result<()> {
    use vos::registry::{RegistryRef, Status};
    use std::collections::HashSet;

    let local_cfg = crate::commands::space::subscriptions::load(data_dir).unwrap_or_default();
    if local_cfg.is_filtering() {
        tracing::info!(
            "subscriptions filter active — {} agent(s)",
            local_cfg.subscriptions.len(),
        );
    }

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let agents =
        vos::block_on(reg.agents(&mut &*node)).map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    // Set of svc_ids the catalog knows about — used at the
    // end to sweep orphaned redbs into trash. We add to this
    // even for skipped agents (subscriptions filter, missing
    // blob, …) so we don't accidentally trash their state.
    let mut live_svc_ids: HashSet<u32> = HashSet::new();
    live_svc_ids.insert(ServiceId::REGISTRY.0);
    if has_hyperspace {
        // The hyperspace registry replica owns its own redb at
        // svc_id 1; protect it from the orphan sweep.
        live_svc_ids.insert(ServiceId::HYPERSPACE_REGISTRY.0);
    }

    let agent_names: Vec<String> = agents.iter().map(|a| a.instance_name.clone()).collect();
    for a in agents.iter() {
        let svc_id = instance_service_id(&a.instance_name, local_prefix);
        live_svc_ids.insert(svc_id.0);
    }

    // Contested raft bootstraps always defer at boot (their grace
    // spans reconcile passes); the throwaway map just satisfies the
    // protocol — the runtime reconciler owns the durable counters.
    let mut boot_grace = BootGrace::new();
    for a in agents {
        if !local_cfg.should_spawn(&a.instance_name) {
            tracing::debug!("skipping '{}' (not subscribed)", a.instance_name);
            continue;
        }
        // Raft rows resolve their member seed first — see the
        // runtime reconciler for the full rationale.
        let raft_members = if consistency_from_u8(a.consistency) == Some(Consistency::Raft) {
            if !blob_store::cache_path_for(&BlobHash(a.program_hash)).exists() {
                tracing::warn!(
                    "skipping agent '{}' — program blob {} not in local cache",
                    a.instance_name,
                    BlobHash(a.program_hash),
                );
                continue;
            }
            match raft_members_for_row(node, data_dir, &a, local_prefix, &mut boot_grace) {
                Ok(RaftSeed::Members(m)) => Some(m),
                Ok(RaftSeed::Defer(reason)) => {
                    tracing::info!(
                        "agent '{}' (raft) deferred to the runtime reconciler: {reason}",
                        a.instance_name,
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!("agent '{}' (raft) deferred: {e}", a.instance_name);
                    continue;
                }
            }
        } else {
            None
        };
        match agent_config_from_row(data_dir, &a, policies)? {
            RowConfig::Ready(cfg) => {
                let mut cfg = *cfg;
                if let Some(members) = raft_members {
                    cfg.members = members;
                }
                let svc_id = instance_service_id(&a.instance_name, local_prefix);
                let id = node.register_at_id(cfg, svc_id);
                tracing::info!(
                    "agent '{}' as {id} ({})",
                    a.instance_name,
                    crate::commands::space::common::consistency_name(a.consistency),
                );
            }
            RowConfig::MissingBlob => {
                tracing::warn!(
                    "skipping agent '{}' — program blob {} not in local cache",
                    a.instance_name,
                    BlobHash(a.program_hash),
                );
            }
            RowConfig::BadConsistency => {
                tracing::warn!(
                    "skipping agent '{}' — unknown consistency {}",
                    a.instance_name,
                    a.consistency,
                );
            }
        }
    }

    // Hyperspace mode: advertise every local agent into the
    // hyperspace registry so cross-space `resolve` calls land on the
    // right host. Best-effort — failures log a warning but don't
    // abort boot, since the local space still works without
    // cross-space addressing.
    if has_hyperspace {
        let hs_reg = RegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
        for name in agent_names {
            match vos::block_on(hs_reg.register_remote(
                &mut &*node,
                name.clone(),
                local_prefix as u32,
            )) {
                Ok(Status::Ok) => {
                    tracing::info!("hyperspace: registered '{name}' @ prefix {local_prefix:#06x}",)
                }
                Ok(other) => {
                    tracing::warn!("hyperspace: register_remote('{name}') returned status {other}",)
                }
                Err(e) => tracing::warn!("hyperspace: register_remote('{name}') failed: {e}",),
            }
        }
    }

    // Sweep `agents/` for redbs whose svc_id no longer maps to
    // a catalog entry — the trace left by past `space uninstall`
    // calls. Move them to `<data_dir>/trash/<svc_id>.redb` so
    // a future `--undo` (or just an `ls`) can recover the bytes
    // instead of finding orphans.
    sweep_orphan_redbs(data_dir, &live_svc_ids);

    Ok(())
}

/// How often the idle hook re-runs the spawn-reconcile pass. The
/// pass is a single local registry invoke plus a hash-set probe
/// per row, so a low couple-of-seconds cadence keeps freshly
/// installed agents snappy without measurable idle cost.
const SPAWN_RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the leader commits a chronos `advance`. This is a keepalive
/// cadence, deliberately NOT the 250 ms slot rate: every state-changing advance
/// is a raft commit, so feeding the clock at 4 Hz would be 4 commits/s/space —
/// too heavy for a chat workload. One commit/second bounds clock freshness to
/// ~1 s while folding roughly one entropy epoch per commit. Piggybacking the
/// slot stamp on the msg-ctl commits a space already makes (sub-second freshness
/// with no extra commits) is the future optimisation; this is the idle-keepalive
/// half of that design.
const CHRONOS_FEED_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// Outcome of resolving one registry `AgentRow` into a spawnable
/// [`AgentConfig`].
enum RowConfig {
    Ready(Box<AgentConfig>),
    /// Program blob not in the local cache. On a joiner the row
    /// can arrive via registry sync before the operator has the
    /// blob, so this is retryable, not fatal.
    MissingBlob,
    /// Unrecognized consistency discriminant.
    BadConsistency,
}

/// Build the `AgentConfig` for one registry row — blob lookup,
/// transpile, persistence/replication wiring, init args, and
/// on_start payloads. Shared by the boot-time
/// `spawn_installed_agents` scan and the runtime
/// `reconcile_installed_agents` pass so both spawn identically.
fn agent_config_from_row(
    data_dir: &std::path::Path,
    a: &vos::registry::AgentRow,
    policies: &AgentPolicies,
) -> anyhow::Result<RowConfig> {
    let program_hash = BlobHash(a.program_hash);
    let elf = match blob_store::cache_get(&program_hash)? {
        Some(b) => b,
        None => return Ok(RowConfig::MissingBlob),
    };
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow::anyhow!("transpile {}: {e:?}", a.instance_name))?;

    let Some(consistency) = consistency_from_u8(a.consistency) else {
        return Ok(RowConfig::BadConsistency);
    };

    let needs_persistence = matches!(
        consistency,
        Consistency::Local | Consistency::Crdt | Consistency::Raft
    );
    let needs_replication = matches!(consistency, Consistency::Crdt | Consistency::Raft);
    let mut cfg = AgentConfig::new(blob)
        .with_name(a.instance_name.clone())
        .with_consistency(consistency);
    if needs_persistence {
        cfg = cfg.persist(data_dir);
    }
    if needs_replication {
        cfg = cfg.with_replication_id(a.replication_id);
    }
    // A node-confined (Local/Ephemeral) agent opts out of the device gate so
    // remote peers can reach it — the network-served bridges. No-op for
    // Crdt/Raft (never confined).
    if a.network_reachable {
        cfg = cfg.network_reachable();
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
    match payload_codec::decode(&a.install_payloads) {
        Ok(payloads) if !payloads.is_empty() => {
            cfg = cfg.with_init_payloads(payloads);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "agent '{}' has unparseable install_payloads, ignoring: {e}",
                a.instance_name,
            );
        }
    }

    // Node-local manifest policy (never replicated): periodic `tick` cadence
    // and the bounded outbound-relay caps.
    if let Some(policy) = policies.get(&a.instance_name) {
        if let Some(ms) = policy.tick_ms {
            cfg = cfg.with_tick_ms(ms);
        }
        if !policy.intra_caps.is_empty() {
            cfg = cfg.with_intra_caps(policy.intra_caps.clone());
        }
    }
    Ok(RowConfig::Ready(Box::new(cfg)))
}

/// Per-voter wait for a `RaftStatusReq` answer. Probes run on the
/// router thread (routing paused) against already-connected peers
/// only, so the worst case per pass is a handful of sub-second
/// waits on connected-but-slow voters.
const RAFT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

/// Wait for a `RaftJoinReq` answer — the leader appends a joint
/// ConfigChange before replying, so give it a little longer than a
/// status probe.
const RAFT_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Consecutive passes a contested bootstrap decision must hold
/// before acting on it. "Every other voter is connected and
/// confirmed absent" can be transiently true while a peer is still
/// spawning its own replica (boot ordering, spawn-batch cap); the
/// grace keeps a momentary view from re-genesis-ing a group that is
/// about to answer.
const RAFT_BOOTSTRAP_GRACE_PASSES: u32 = 2;

/// Cap on status probes per row per pass, bounding router-thread
/// stall when a space has many voters.
const MAX_RAFT_PROBES: usize = 5;

/// Decision for spawning one raft-consistency row, produced by
/// [`decide_raft_spawn`] from the registry voter set + the peers'
/// answers. The IO around it (probes, the join handshake, config
/// seeding, grace counting) lives in [`raft_members_for_row`].
#[derive(Debug, PartialEq, Eq)]
enum RaftPlan {
    /// Spawn now with this member seed (anchored restart, or a
    /// rejoin the group still counts us in).
    Spawn(Vec<u16>),
    /// A live group exists and `leader` can admit us; join first,
    /// then spawn. `known` is the freshest member view we probed —
    /// the post-join fallback seed if the leader can't be
    /// re-probed (never spawn a joiner with just `[local]`: a
    /// one-element seed self-elects and forks the group).
    Join { leader: u16, known: Vec<u16> },
    /// Brand-new group this node should create. `contested` means
    /// other voters exist (all confirmed absent) — apply the
    /// bootstrap grace before acting; uncontested (sole voter) is
    /// immediate.
    Bootstrap { contested: bool },
    /// Not spawnable this pass; retried cheaply on later passes.
    Defer(String),
}

/// Pure decision table for one raft row. `voters` is the sorted,
/// deduped `NODE_ROLE_VOTER` prefix set from the registry;
/// `anchored` means the agent's local db already records a member
/// configuration (so the persisted config — not our seed — governs
/// on spawn); `probes` holds the status answers from every OTHER
/// connected voter, present or absent; `other_voters` is how many
/// other voters exist in total (probes < other_voters means some
/// voter was unreachable, which blocks the contested bootstrap).
fn decide_raft_spawn(
    local: u16,
    voters: &[u16],
    anchored: bool,
    probes: &[(u16, vos::network::RaftStatusReply)],
    other_voters: usize,
) -> RaftPlan {
    use vos::network::RaftRole;

    if !voters.contains(&local) {
        return RaftPlan::Defer(
            "this node is not a voter (enroll it with `vosx space members add-node`)".into(),
        );
    }
    if anchored {
        // The persisted active config supersedes the seed; the
        // voter set just has to be non-empty to spawn the worker.
        return RaftPlan::Spawn(voters.to_vec());
    }
    if voters == [local] {
        return RaftPlan::Bootstrap { contested: false };
    }

    // A live group somewhere wins over any bootstrap theory.
    let live: Vec<&(u16, vos::network::RaftStatusReply)> =
        probes.iter().filter(|(_, r)| r.present).collect();
    for (_, reply) in &live {
        if reply.members.contains(&local) {
            // The group already counts us as a member (a wiped db
            // rejoining): spawn and let the leader catch us up.
            return RaftPlan::Spawn(reply.members.clone());
        }
    }
    if let Some((v, reply)) = live.iter().find(|(_, r)| r.role == RaftRole::Leader) {
        return RaftPlan::Join {
            leader: *v,
            known: reply.members.clone(),
        };
    }
    if let Some((_, reply)) = live.iter().find(|(_, r)| r.leader_hint.is_some()) {
        return RaftPlan::Join {
            leader: reply.leader_hint.expect("filtered on is_some"),
            known: reply.members.clone(),
        };
    }
    if !live.is_empty() {
        return RaftPlan::Defer("group has no leader yet (election in progress)".into());
    }

    // No live group anywhere we could see. Only the smallest voter
    // may create one, and only with positive confirmation from
    // every other voter — an "absent" from a status probe also
    // covers "host up but replica not spawned yet", hence the
    // caller-side grace. A wiped smallest-voter racing that window
    // can still re-genesis a group it can't see; the durable fix is
    // a bootstrap anchor in the registry row (with signed registry
    // ops), not reachable from this layer.
    let smallest = *voters.iter().min().expect("voters contains local");
    if smallest != local {
        return RaftPlan::Defer(format!(
            "waiting for voter {smallest:#06x} to bootstrap the group",
        ));
    }
    if probes.len() < other_voters {
        return RaftPlan::Defer(format!(
            "cannot locate the group — {} of {other_voters} other voter(s) unreachable",
            other_voters - probes.len(),
        ));
    }
    RaftPlan::Bootstrap { contested: true }
}

/// Outcome of [`raft_members_for_row`]: either the member seed to
/// spawn with, or the reason the row stays deferred this pass.
enum RaftSeed {
    Members(Vec<u16>),
    Defer(String),
}

/// Grace counters for contested bootstraps, keyed like the damping
/// set. Entries are removed when the row spawns or the decision
/// changes away from bootstrap.
type BootGrace = std::collections::HashMap<(String, [u8; 32]), u32>;

/// Run the membership protocol for one raft row: read the voter
/// set, probe connected voters for the group, join a live group
/// through its leader, or anchor + bootstrap a brand-new one.
/// Called before the row's (expensive) transpile so a defer costs
/// little, and so the join handshake only ever fires when the
/// spawn follows it.
fn raft_members_for_row(
    node: &VosNode,
    data_dir: &std::path::Path,
    a: &vos::registry::AgentRow,
    local_prefix: u16,
    boot_grace: &mut BootGrace,
) -> anyhow::Result<RaftSeed> {
    use vos::registry::{MEMBER_KIND_NODE, NODE_ROLE_VOTER, RegistryRef};

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let rows = vos::block_on(reg.members(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query members: {e}"))?;
    let mut voters: Vec<u16> = rows
        .iter()
        .filter(|m| m.kind == MEMBER_KIND_NODE && m.role == NODE_ROLE_VOTER)
        .map(|m| m.prefix)
        .collect();
    voters.sort_unstable();
    voters.dedup();

    let svc_id = instance_service_id(&a.instance_name, local_prefix);
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", svc_id.0));
    let anchored = db_path.exists()
        && vos::raft::persisted_membership(&db_path)
            .unwrap_or_default()
            .is_some();

    let net = node.network();
    let other_voters = voters.iter().filter(|&&v| v != local_prefix).count();
    let mut probes: Vec<(u16, vos::network::RaftStatusReply)> = Vec::new();
    if let Some(net) = net.as_ref() {
        for &v in voters
            .iter()
            .filter(|&&v| v != local_prefix)
            .take(MAX_RAFT_PROBES)
        {
            let Some(peer) = net.peer_for_prefix(v) else {
                continue; // not connected — can't confirm anything about it
            };
            if let Ok(reply) = net
                .send_raft_status_req(peer, a.replication_id)
                .recv_timeout(RAFT_PROBE_TIMEOUT)
            {
                probes.push((v, reply));
            }
        }
    }

    let grace_key = (a.instance_name.clone(), a.program_hash);
    let plan = decide_raft_spawn(local_prefix, &voters, anchored, &probes, other_voters);
    if !matches!(plan, RaftPlan::Bootstrap { contested: true }) {
        boot_grace.remove(&grace_key);
    }
    match plan {
        RaftPlan::Spawn(members) => Ok(RaftSeed::Members(members)),
        RaftPlan::Defer(reason) => Ok(RaftSeed::Defer(reason)),
        RaftPlan::Bootstrap { contested } => {
            if contested {
                let passes = boot_grace.entry(grace_key.clone()).or_insert(0);
                *passes += 1;
                if *passes < RAFT_BOOTSTRAP_GRACE_PASSES {
                    return Ok(RaftSeed::Defer(format!(
                        "group absent on every other voter — confirming for {} more pass(es) \
                         before bootstrapping",
                        RAFT_BOOTSTRAP_GRACE_PASSES - *passes,
                    )));
                }
                boot_grace.remove(&grace_key);
            }
            // Anchor the configuration BEFORE the first spawn: a
            // solo group that never changes membership writes no
            // ConfigChange entry, and without the seeded row a
            // restart would re-derive its member set from whatever
            // the registry says by then — which may have grown,
            // leaving the group unable to elect (and the pending
            // joiner with no leader to join).
            vos::raft::seed_initial_config(&db_path, &[local_prefix])
                .map_err(|e| anyhow::anyhow!("seed raft config for '{}': {e}", a.instance_name))?;
            Ok(RaftSeed::Members(vec![local_prefix]))
        }
        RaftPlan::Join { leader, known } => {
            let Some(net) = net else {
                return Ok(RaftSeed::Defer("no network attached".into()));
            };
            join_raft_group(&net, a, local_prefix, leader, known)
        }
    }
}

/// Ask the group's leader to admit this node as a voter, following
/// at most one leadership redirect. On `Accepted`, re-probe the
/// leader for the freshest member set (a joiner admitted between
/// our probe and our join must be in our seed, or we'd reject its
/// votes until the log catches up) and fall back to the probed
/// `known` view when the re-probe fails.
fn join_raft_group(
    net: &std::sync::Arc<vos::network::Network>,
    a: &vos::registry::AgentRow,
    local_prefix: u16,
    mut leader: u16,
    known: Vec<u16>,
) -> anyhow::Result<RaftSeed> {
    use vos::network::RaftJoinResult;

    for _redirect in 0..2 {
        let Some(peer) = net.peer_for_prefix(leader) else {
            return Ok(RaftSeed::Defer(format!(
                "raft leader {leader:#06x} is not connected",
            )));
        };
        let rx = net.send_raft_join_req(peer, a.replication_id, local_prefix);
        match rx.recv_timeout(RAFT_JOIN_TIMEOUT) {
            Ok(RaftJoinResult::Accepted { .. }) => {
                let mut members = match net
                    .send_raft_status_req(peer, a.replication_id)
                    .recv_timeout(RAFT_PROBE_TIMEOUT)
                {
                    Ok(st) if st.present && !st.members.is_empty() => st.members,
                    _ => known,
                };
                members.push(local_prefix);
                members.sort_unstable();
                members.dedup();
                tracing::info!(
                    "agent '{}': joined raft group as voter (leader {leader:#06x}, {} member(s))",
                    a.instance_name,
                    members.len(),
                );
                return Ok(RaftSeed::Members(members));
            }
            Ok(RaftJoinResult::NotLeader {
                leader_hint: Some(h),
            }) if h != leader => {
                leader = h; // follow one redirect
            }
            Ok(RaftJoinResult::NotLeader { .. }) => {
                return Ok(RaftSeed::Defer(
                    "leadership moved during the join handshake".into(),
                ));
            }
            Ok(RaftJoinResult::Busy) => {
                return Ok(RaftSeed::Defer(
                    "another membership change is in flight".into(),
                ));
            }
            Ok(RaftJoinResult::UnknownGroup) => {
                return Ok(RaftSeed::Defer(format!(
                    "peer {leader:#06x} no longer runs the group",
                )));
            }
            Ok(RaftJoinResult::NotAuthorized) => {
                // Permanent refusal — this node isn't an enrolled voter.
                // Don't retry; an admin must enrol it first.
                return Ok(RaftSeed::Defer(format!(
                    "this node ({local_prefix:#06x}) is not enrolled as a voter for \
                     agent '{}'; an admin must run `vosx space members add <peer> \
                     --role voter`",
                    a.instance_name,
                )));
            }
            Err(_) => {
                return Ok(RaftSeed::Defer("join request timed out".into()));
            }
        }
    }
    Ok(RaftSeed::Defer("leader redirects did not converge".into()))
}

/// Cap on agents brought up in a single reconcile pass. The pass
/// runs on the router thread (routing paused), and each spawn
/// costs an ELF transpile + redb open + thread spawn — bounding
/// the batch keeps a burst of synced rows from freezing routing,
/// and rate-limits how fast a (possibly hostile) flood of
/// registry rows can amplify into local threads. Remaining rows
/// spawn on subsequent passes.
const MAX_SPAWNS_PER_PASS: usize = 4;

/// A row condition already reported (and, for hard failures,
/// permanently skipped): the damping key is `(instance_name,
/// program_hash, kind)`, so reinstalling the same name with a new
/// blob re-attempts and re-reports.
type RowDamping = std::collections::HashSet<(String, [u8; 32], RowNote)>;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum RowNote {
    /// Hard per-row failure (transpile error, cache IO, bad
    /// consistency, ServiceId collision). Warned once, then the
    /// row is skipped outright — no point re-running the failing
    /// work every pass.
    Failed,
    /// Program blob not cached yet. Warned once; the (cheap)
    /// cache probe keeps retrying, so the row spawns if the blob
    /// appears later.
    AwaitingBlob,
    /// Raft row whose membership protocol deferred the spawn
    /// (not a voter yet, group not located, join in progress…).
    /// Warned once with the current reason; later passes log the
    /// (possibly different) reason at debug. Cleared on spawn so
    /// a later wedge re-warns.
    RaftWaiting,
}

/// One runtime spawn-reconcile pass: query the registry for
/// installed agents and bring up any that aren't running yet —
/// the runtime twin of [`spawn_installed_agents`], called from
/// `run_forever_with`'s tick hook so agents installed (or
/// CRDT-synced from a peer) after boot become usable without a
/// restart.
///
/// Idempotent by construction: rows whose deterministic ServiceId
/// is already registered on the node are skipped, including
/// agents an operator stopped with `vosx <agent> stop` (their
/// slot stays taken — a restart revives them, not this pass).
/// At most [`MAX_SPAWNS_PER_PASS`] rows spawn per pass.
///
/// Trust model: registry rows replicate via CRDT sync with no
/// per-row author check — the Admin gate on `install` fires only
/// on the originating node. What bounds this pass is the local
/// blob cache (it never fetches code; only already-cached
/// programs can spawn), the subscriptions filter, and the
/// per-pass cap. Until registry ops are author-signed, any space
/// member can make peers spawn extra instances of programs those
/// peers already hold.
///
/// Uninstall is still restart-bound: this pass only spawns, it
/// never stops agents whose rows disappeared.
fn reconcile_installed_agents(
    node: &mut VosNode,
    data_dir: &std::path::Path,
    local_prefix: u16,
    has_hyperspace: bool,
    local_cfg: &crate::commands::space::subscriptions::LocalConfig,
    damped: &mut RowDamping,
    boot_grace: &mut BootGrace,
    policies: &AgentPolicies,
) -> anyhow::Result<()> {
    use vos::registry::{RegistryRef, Status};

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let agents =
        vos::block_on(reg.agents(&mut &*node)).map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    let mut spawned_this_pass = 0usize;
    for a in agents {
        if spawned_this_pass >= MAX_SPAWNS_PER_PASS {
            break;
        }
        if !local_cfg.should_spawn(&a.instance_name) {
            continue;
        }
        let key = |note: RowNote| (a.instance_name.clone(), a.program_hash, note);
        if damped.contains(&key(RowNote::Failed)) {
            continue;
        }
        let svc_id = instance_service_id(&a.instance_name, local_prefix);
        if node.has_agent(svc_id) {
            // Usually this row's own agent. A *different* occupying
            // name means a ~15-bit instance-name hash collision:
            // name-deterministic, so the row can never spawn on any
            // node — surface it instead of skipping silently.
            let occupant = node.agent_name_for(svc_id.0);
            if occupant
                .as_deref()
                .is_some_and(|o| !o.eq_ignore_ascii_case(&a.instance_name))
                && damped.insert(key(RowNote::Failed))
            {
                tracing::warn!(
                    "agent '{}' can never spawn — its ServiceId collides with installed \
                     agent '{}' (rename one of them)",
                    a.instance_name,
                    occupant.unwrap_or_default(),
                );
            }
            continue;
        }
        // Raft rows run the membership protocol BEFORE the
        // (expensive) transpile: a deferred row must not
        // re-transpile every 2 s, and the join handshake must only
        // fire when the spawn follows it. The blob probe comes
        // first for the same reason — joining a group we can't
        // spawn into would stall its quorum.
        let raft_members = if consistency_from_u8(a.consistency) == Some(Consistency::Raft) {
            if !blob_store::cache_path_for(&BlobHash(a.program_hash)).exists() {
                if damped.insert(key(RowNote::AwaitingBlob)) {
                    tracing::warn!(
                        "agent '{}' pending — program blob {} not in the local cache \
                         (no peer fetch exists yet); it spawns when the blob appears",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                }
                continue;
            }
            match raft_members_for_row(node, data_dir, &a, local_prefix, boot_grace) {
                Ok(RaftSeed::Members(m)) => {
                    damped.remove(&key(RowNote::RaftWaiting));
                    Some(m)
                }
                Ok(RaftSeed::Defer(reason)) => {
                    if damped.insert(key(RowNote::RaftWaiting)) {
                        tracing::warn!("agent '{}' (raft) deferred: {reason}", a.instance_name);
                    } else {
                        tracing::debug!("agent '{}' (raft) deferred: {reason}", a.instance_name);
                    }
                    continue;
                }
                Err(e) => {
                    if damped.insert(key(RowNote::RaftWaiting)) {
                        tracing::warn!("agent '{}' (raft) deferred: {e}", a.instance_name);
                    }
                    continue;
                }
            }
        } else {
            None
        };
        match agent_config_from_row(data_dir, &a, policies) {
            Ok(RowConfig::Ready(cfg)) => {
                let mut cfg = *cfg;
                if let Some(members) = raft_members {
                    cfg.members = members;
                }
                let id = node.register_at_id(cfg, svc_id);
                spawned_this_pass += 1;
                tracing::info!(
                    "agent '{}' spawned at runtime as {id} ({})",
                    a.instance_name,
                    crate::commands::space::common::consistency_name(a.consistency),
                );
                if has_hyperspace {
                    let hs_reg = RegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
                    match vos::block_on(hs_reg.register_remote(
                        &mut &*node,
                        a.instance_name.clone(),
                        local_prefix as u32,
                    )) {
                        Ok(Status::Ok) => {}
                        Ok(other) => tracing::warn!(
                            "hyperspace: register_remote('{}') returned status {other}",
                            a.instance_name,
                        ),
                        Err(e) => tracing::warn!(
                            "hyperspace: register_remote('{}') failed: {e}",
                            a.instance_name,
                        ),
                    }
                }
            }
            Ok(RowConfig::MissingBlob) => {
                if damped.insert(key(RowNote::AwaitingBlob)) {
                    tracing::warn!(
                        "agent '{}' pending — program blob {} not in the local cache \
                         (no peer fetch exists yet); it spawns when the blob appears",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                }
            }
            Ok(RowConfig::BadConsistency) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!(
                        "skipping agent '{}' — unknown consistency {}",
                        a.instance_name,
                        a.consistency,
                    );
                }
            }
            Err(e) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!("agent '{}' failed to spawn: {e}", a.instance_name);
                }
            }
        }
    }
    Ok(())
}

/// Walk `<data_dir>/agents/`, trash any `<svc_id>.redb` whose
/// id isn't in `live`. Best-effort — failures log a warning
/// but don't abort the daemon boot. The registry's own redb
/// (svc_id 0) is always live, by virtue of being added to
/// `live` before this runs.
fn sweep_orphan_redbs(data_dir: &std::path::Path, live: &std::collections::HashSet<u32>) {
    let agents_dir = data_dir.join("agents");
    let entries = match std::fs::read_dir(&agents_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let trash = data_dir.join("trash");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(stem) = name_str.strip_suffix(".redb") else {
            continue;
        };
        let Ok(svc_id) = u32::from_str_radix(stem, 16) else {
            continue;
        };
        if live.contains(&svc_id) {
            continue;
        }
        if std::fs::create_dir_all(&trash).is_err() {
            continue;
        }
        let dest = trash.join(name_str);
        match std::fs::rename(entry.path(), &dest) {
            Ok(()) => tracing::info!(
                "moved orphan redb to trash: svc_id={svc_id:#010x}, path={}",
                dest.display(),
            ),
            Err(e) => tracing::warn!(
                "failed to trash orphan redb {}: {e}",
                entry.path().display(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::network::{RaftRole, RaftStatusReply};

    fn status(role: RaftRole, members: Vec<u16>, leader_hint: Option<u16>) -> RaftStatusReply {
        RaftStatusReply {
            present: true,
            role,
            current_term: 1,
            commit_index: 1,
            last_log_index: 1,
            members,
            leader_hint,
        }
    }

    fn absent() -> RaftStatusReply {
        RaftStatusReply {
            present: false,
            role: RaftRole::Follower,
            current_term: 0,
            commit_index: 0,
            last_log_index: 0,
            members: Vec::new(),
            leader_hint: None,
        }
    }

    #[test]
    fn non_voter_defers() {
        let plan = decide_raft_spawn(0x0003, &[0x0001, 0x0002], false, &[], 2);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn anchored_db_spawns_with_voter_seed() {
        // The persisted config governs; the seed just has to be the
        // current voter set so the worker spawns in multi-mode.
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002], true, &[], 1);
        assert_eq!(plan, RaftPlan::Spawn(vec![0x0001, 0x0002]));
    }

    #[test]
    fn sole_voter_bootstraps_immediately() {
        let plan = decide_raft_spawn(0x0001, &[0x0001], false, &[], 0);
        assert_eq!(plan, RaftPlan::Bootstrap { contested: false });
    }

    #[test]
    fn live_group_counting_us_respawns_with_its_members() {
        // A wiped node the group still counts as a voter rejoins by
        // spawning with the group's view; the leader catches it up.
        let probes = vec![(
            0x0001,
            status(RaftRole::Leader, vec![0x0001, 0x0002], Some(0x0001)),
        )];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(plan, RaftPlan::Spawn(vec![0x0001, 0x0002]));
    }

    #[test]
    fn live_group_led_by_probed_voter_joins_there() {
        let probes = vec![(0x0001, status(RaftRole::Leader, vec![0x0001], Some(0x0001)))];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(
            plan,
            RaftPlan::Join {
                leader: 0x0001,
                known: vec![0x0001],
            },
        );
    }

    #[test]
    fn live_group_follower_redirects_join_to_hint() {
        // Probed a follower of a three-voter group; its hint names
        // the leader we didn't probe.
        let probes = vec![(
            0x0002,
            status(RaftRole::Follower, vec![0x0001, 0x0002], Some(0x0001)),
        )];
        let plan = decide_raft_spawn(0x0003, &[0x0001, 0x0002, 0x0003], false, &probes, 2);
        assert_eq!(
            plan,
            RaftPlan::Join {
                leader: 0x0001,
                known: vec![0x0001, 0x0002],
            },
        );
    }

    #[test]
    fn live_group_without_leader_defers() {
        let probes = vec![(0x0001, status(RaftRole::Candidate, vec![0x0001], None))];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn absent_everywhere_only_smallest_voter_bootstraps_contested() {
        let probes = vec![(0x0002, absent())];
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(plan, RaftPlan::Bootstrap { contested: true });

        let probes = vec![(0x0001, absent())];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn unreachable_voter_blocks_contested_bootstrap() {
        // Two other voters, only one answered: no positive
        // confirmation, no bootstrap — the group may live on the
        // silent one.
        let probes = vec![(0x0002, absent())];
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002, 0x0003], false, &probes, 2);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }
}
