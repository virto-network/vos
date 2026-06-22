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
    let hyperspace = parsed_manifest
        .as_ref()
        .and_then(|(m, _)| m.hyperspace.clone());

    // Always attach a libp2p network — even local-only spaces
    // bind a loopback port so client commands (`space publish`,
    // `space install`, etc.) have an endpoint to dial.
    let network = build_network_for_daemon(entry, &data_dir, &args.listen, &args.connect)?;
    let local_prefix = network.local_prefix();

    let mut node = VosNode::with_prefix(local_prefix);
    let cfg = AgentConfig::new(blob.clone())
        .with_consistency(Consistency::Crdt)
        .with_replication_id(replication_id)
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
        )?;
    }

    // Spawn every installed agent recorded in the registry.
    // Each gets a deterministic per-node ServiceId so its redb
    // path is stable across restarts.
    spawn_installed_agents(&mut node, &data_dir, local_prefix, hyperspace.is_some())?;

    // Sprint 2 — first-boot admin bootstrap. `space new` records
    // the creator's client PeerId in `admin_bootstrap.txt`. We
    // grant them AUTH_ROLE_ADMIN via a local invoke (which
    // bypasses the dispatch-layer auth gate — that only fires
    // for libp2p-traversing calls), then delete the file so
    // subsequent boots are no-ops.
    consume_admin_bootstrap(&node, &data_dir, local_prefix)?;

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
        let mut query_warned = false;
        let mut last_pass = std::time::Instant::now();
        node.run_forever_with(|n| {
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

/// Wait briefly for the swarm to bind, then write the endpoint
/// descriptor so clients can find us.
/// Sprint 2 — consume the `admin_bootstrap.txt` file that
/// `space new` writes alongside `node.key`, granting the recorded
/// PeerId `AUTH_ROLE_ADMIN` in the registry's `auth_grants`
/// table. The grant goes through a local invoke so it bypasses
/// the dispatch-layer auth gate (which only applies to libp2p-
/// originated calls). Idempotent — if the file is missing, this
/// is a no-op. Deletes the file after a successful grant so
/// subsequent boots skip this work.
fn consume_admin_bootstrap(
    node: &VosNode,
    data_dir: &std::path::Path,
    daemon_prefix: u16,
) -> anyhow::Result<()> {
    use space_registry::{AUTH_ROLE_ADMIN, STATUS_OK, SpaceRegistryRef};
    let bootstrap_path = data_dir.join("admin_bootstrap.txt");
    let peer_id_str = match std::fs::read_to_string(&bootstrap_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => anyhow::bail!("read {}: {e}", bootstrap_path.display()),
    };
    if peer_id_str.is_empty() {
        let _ = std::fs::remove_file(&bootstrap_path);
        return Ok(());
    }
    let peer_id: libp2p::PeerId = peer_id_str
        .parse()
        .map_err(|e| anyhow::anyhow!("parse {peer_id_str} as PeerId: {e}"))?;

    let reg = SpaceRegistryRef::at(ServiceId::new(
        daemon_prefix,
        ServiceId::REGISTRY.local_id(),
    ));
    let status = vos::block_on(reg.grant_role(&mut &*node, peer_id.to_bytes(), AUTH_ROLE_ADMIN))
        .map_err(|e| anyhow::anyhow!("grant_role bootstrap: {e}"))?;
    if status != STATUS_OK {
        anyhow::bail!("grant_role returned status {status}");
    }
    tracing::info!(%peer_id, "auth: granted ADMIN to space creator (bootstrap)");

    // One-shot — delete after successful grant. Subsequent boots
    // see the file gone and skip; if the registry already has
    // grants for this peer, the grant call above is idempotent.
    let _ = std::fs::remove_file(&bootstrap_path);
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
) -> anyhow::Result<()> {
    use space_registry::{STATUS_OK, SpaceRegistryRef};
    use std::collections::HashSet;

    let local_cfg = crate::commands::space::subscriptions::load(data_dir).unwrap_or_default();
    if local_cfg.is_filtering() {
        tracing::info!(
            "subscriptions filter active — {} agent(s)",
            local_cfg.subscriptions.len(),
        );
    }

    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
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

    for a in agents {
        if !local_cfg.should_spawn(&a.instance_name) {
            tracing::debug!("skipping '{}' (not subscribed)", a.instance_name);
            continue;
        }
        match agent_config_from_row(data_dir, &a)? {
            RowConfig::Ready(cfg) => {
                let svc_id = instance_service_id(&a.instance_name, local_prefix);
                let id = node.register_at_id(*cfg, svc_id);
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
        let hs_reg = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
        for name in agent_names {
            match vos::block_on(hs_reg.register_remote(
                &mut &*node,
                name.clone(),
                local_prefix as u32,
            )) {
                Ok(STATUS_OK) => {
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
    a: &space_registry::AgentRow,
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

    let mut cfg = AgentConfig::new(blob)
        .with_name(a.instance_name.clone())
        .with_consistency(consistency);
    if matches!(
        consistency,
        Consistency::Local | Consistency::Crdt | Consistency::Raft
    ) {
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
    Ok(RowConfig::Ready(Box::new(cfg)))
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
) -> anyhow::Result<()> {
    use space_registry::{STATUS_OK, SpaceRegistryRef};

    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
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
        match agent_config_from_row(data_dir, &a) {
            Ok(RowConfig::Ready(cfg)) => {
                let id = node.register_at_id(*cfg, svc_id);
                spawned_this_pass += 1;
                tracing::info!(
                    "agent '{}' spawned at runtime as {id} ({})",
                    a.instance_name,
                    crate::commands::space::common::consistency_name(a.consistency),
                );
                if has_hyperspace {
                    let hs_reg = SpaceRegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
                    match vos::block_on(hs_reg.register_remote(
                        &mut &*node,
                        a.instance_name.clone(),
                        local_prefix as u32,
                    )) {
                        Ok(STATUS_OK) => {}
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
