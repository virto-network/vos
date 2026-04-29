//! `vosx start [<manifest>]` — boot a space defined by a TOML
//! manifest. Auto-spawns the hyperspace registry when declared,
//! announces every local service into it, runs forever (or
//! until idle when no network is attached).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode, WorkerConfig};
use vos::value::Args;

use crate::hyperspace::{flush_registry_announces, heartbeat_loop, AnnouncePlan};
use crate::manifest::{
    apply_init, encode_on_start, resolve_entry_path, resolve_replication_id, toml_to_value,
    ConsistencyDef, Manifest,
};
use crate::network::start_network_if_needed;
use crate::util::{die, exit_with_status, format_provides, hex32, load_blob, load_file};

pub fn run(
    manifest: &Manifest,
    dir: &Path,
    data_dir_cli: Option<&Path>,
    no_persist: bool,
    listen_cli: &[String],
    connect_cli: &[String],
) {
    eprintln!(
        "vosx: starting space '{}' ({} agent(s), {} worker(s))",
        manifest.space,
        manifest.agent.len(),
        manifest.worker.len(),
    );
    if let Some(hs) = &manifest.hyperspace {
        eprintln!(
            "vosx: hyperspace '{hs}' (declared; registry inherited from there \
             once networking lands)",
        );
    }

    // Where this node lives on disk: CLI --data-dir wins; otherwise
    // fall back to the manifest's [node].data_dir. Used for the
    // libp2p identity regardless of --no-persist; --no-persist only
    // disables *actor state* persistence below.
    let data_dir = data_dir_cli
        .map(|p| p.to_path_buf())
        .or_else(|| manifest.node.data_dir.clone());

    // Actor state persistence honours --no-persist. Network identity
    // does not — peers that get a fresh PeerId on every restart are
    // useless for any kind of stable addressing.
    let state_dir = if no_persist { None } else { data_dir.clone() };

    let network = start_network_if_needed(manifest, data_dir.as_deref(), listen_cli, connect_cli);

    check_unique_names(manifest);

    // Use the network's prefix (when present) so all locally-
    // allocated ServiceIds carry the right high 16 bits.
    let mut node = match &network {
        Some(net) => VosNode::with_prefix(net.local_prefix()),
        None => VosNode::new(),
    };
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    let mut provides_map: BTreeMap<String, Vec<u32>> = BTreeMap::new();

    let registry_active = spawn_registry_if_declared(manifest, dir, state_dir.as_deref(), &mut node);
    let mut announces: Vec<AnnouncePlan> = Vec::new();

    register_workers(manifest, dir, state_dir.as_deref(), &mut node,
        &mut name_ids, &mut provides_map);

    register_agents(
        manifest, dir, state_dir.as_deref(), &mut node,
        &mut name_ids, &mut provides_map, registry_active, &mut announces,
    );

    // Hand the network off to the node — both die together at
    // collect time.
    let networked = network.is_some();
    if let Some(net) = network {
        node.attach_network(net);
    }

    if registry_active && !announces.is_empty() {
        flush_registry_announces(&node, &announces);
    }

    let heartbeat = spawn_heartbeat(manifest, &node, &announces, registry_active, networked);

    eprintln!("vosx: running space '{}'...\n", manifest.space);
    if networked {
        eprintln!("vosx: networking on — running until shutdown (Ctrl-C)");
        node.run_forever();
    } else {
        node.run();
    }

    if let Some(h) = heartbeat {
        let _ = h.join();
    }

    let results = node.collect();
    let panics: u32 = results.iter().map(|r| r.panics).sum();
    let mut host_errors = 0usize;
    for r in &results {
        if let Some(err) = &r.error {
            tracing::error!(id = %r.id, "{err}");
            host_errors += 1;
        }
    }
    if host_errors > 0 {
        std::process::exit(2);
    }
    exit_with_status(panics);
}

/// Sanity check: no two declarations share a name across
/// agents, child actors, and workers.
fn check_unique_names(manifest: &Manifest) {
    let mut seen = BTreeMap::<String, &str>::new();
    let mut check = |name: &str, kind: &'static str| {
        if let Some(prev) = seen.insert(name.to_string(), kind) {
            die(&format!(
                "duplicate name '{name}' in manifest (already used as {prev})"
            ));
        }
    };
    for a in &manifest.agent {
        check(&a.name, "agent");
        for child in &a.actors {
            check(&child.name, "actor");
        }
    }
    for w in &manifest.worker {
        check(&w.name, "worker");
    }
}

/// When `hyperspace = "..."` is declared, spin up a CRDT
/// replica of the registry actor at the well-known
/// `ServiceId::REGISTRY` and return `true`. Otherwise `false`.
fn spawn_registry_if_declared(
    manifest: &Manifest,
    dir: &Path,
    state_dir: Option<&Path>,
    node: &mut VosNode,
) -> bool {
    let Some(hyperspace_name) = &manifest.hyperspace else {
        return false;
    };
    let blob_path = match &manifest.registry_blob {
        Some(p) => dir.join(p),
        None => die(&format!(
            "manifest declares hyperspace='{hyperspace_name}' but no \
             `registry_blob` path; phase-2 vosx needs the registry \
             actor's elf until embedding lands",
        )),
    };
    let blob = load_blob(&blob_path);
    let rep_id = registry::replication_id(hyperspace_name);
    let mut cfg = AgentConfig::new(blob)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(rep_id);
    if let Some(d) = state_dir {
        cfg = cfg.persist(d);
    }
    let id = node.register_at_id(cfg, ServiceId::REGISTRY);
    eprintln!(
        "vosx: hyperspace='{hyperspace_name}' registry as {id} (rep_id={})",
        hex32(&rep_id),
    );
    true
}

fn register_workers(
    manifest: &Manifest,
    dir: &Path,
    state_dir: Option<&Path>,
    node: &mut VosNode,
    name_ids: &mut BTreeMap<String, u32>,
    provides_map: &mut BTreeMap<String, Vec<u32>>,
) {
    for w in &manifest.worker {
        let path = resolve_entry_path(&w.name, &w.path, &w.service, dir);
        let mut cfg = if w.init.is_empty() {
            WorkerConfig::new(path)
        } else {
            let mut args = Args::new();
            for (k, v) in &w.init {
                args = args.with(k, toml_to_value(v, name_ids, provides_map));
            }
            WorkerConfig::with_args(path, &args)
        };
        if let Some(d) = state_dir {
            cfg = cfg.persist(d);
        }
        let id = node.register_worker(cfg);
        let role_tag = format_provides(&w.provides);
        eprintln!("vosx: worker '{}' as {id}{role_tag}", w.name);
        name_ids.insert(w.name.clone(), id.0);
        for role in &w.provides {
            provides_map.entry(role.clone()).or_default().push(id.0);
        }
    }
}

fn register_agents(
    manifest: &Manifest,
    dir: &Path,
    state_dir: Option<&Path>,
    node: &mut VosNode,
    name_ids: &mut BTreeMap<String, u32>,
    provides_map: &mut BTreeMap<String, Vec<u32>>,
    registry_active: bool,
    announces: &mut Vec<AnnouncePlan>,
) {
    for a in &manifest.agent {
        // Child actors first so the parent agent's `init` can
        // reference them by name.
        for child in &a.actors {
            let path = resolve_entry_path(&child.name, &child.path, &child.service, dir);
            let elf_data = load_file(&path);
            let blob = load_blob(&path);

            let mut cfg = AgentConfig::new(blob.clone()).with_consistency(a.consistency.into());
            if let Some(d) = state_dir {
                cfg = cfg.persist(d);
            }
            if a.consistency == ConsistencyDef::Crdt {
                if let Some(rep_id) = resolve_replication_id(
                    &child.name,
                    child.replication_id.as_deref(),
                    &blob,
                ) {
                    cfg = cfg.with_replication_id(rep_id);
                }
            }
            cfg = apply_init(cfg, &child.init, &elf_data, name_ids, provides_map);
            if !child.on_start.is_empty() {
                let payloads = encode_on_start(
                    &child.name, &child.on_start, &elf_data, name_ids, provides_map,
                );
                cfg = cfg.with_init_payloads(payloads);
            }

            let id = node.register(cfg);
            let role_tag = format_provides(&child.provides);
            eprintln!(
                "vosx: actor '{}' (child of '{}') as {id} ({:?}){role_tag}",
                child.name, a.name, a.consistency,
            );
            name_ids.insert(child.name.clone(), id.0);
            for role in &child.provides {
                provides_map.entry(role.clone()).or_default().push(id.0);
            }
            if registry_active {
                announces.push(AnnouncePlan {
                    name: format!("{}/{}", a.name, child.name),
                    owner_prefix: id.node_prefix(),
                    service_id: id.local_id(),
                    roles: child.provides.clone(),
                });
            }
        }

        // Then the agent itself.
        let path = resolve_entry_path(&a.name, &a.path, &a.service, dir);
        let elf_data = load_file(&path);
        let blob = load_blob(&path);

        let mut cfg = AgentConfig::new(blob.clone()).with_consistency(a.consistency.into());
        if let Some(d) = state_dir {
            cfg = cfg.persist(d);
        }
        if a.consistency == ConsistencyDef::Crdt {
            if let Some(rep_id) = resolve_replication_id(
                &a.name, a.replication_id.as_deref(), &blob,
            ) {
                cfg = cfg.with_replication_id(rep_id);
            }
        }
        cfg = apply_init(cfg, &a.init, &elf_data, name_ids, provides_map);
        if !a.on_start.is_empty() {
            let payloads = encode_on_start(
                &a.name, &a.on_start, &elf_data, name_ids, provides_map,
            );
            cfg = cfg.with_init_payloads(payloads);
        }

        let id = node.register(cfg);
        let role_tag = format_provides(&a.provides);
        eprintln!("vosx: agent '{}' as {id} ({:?}){role_tag}", a.name, a.consistency);
        name_ids.insert(a.name.clone(), id.0);
        for role in &a.provides {
            provides_map.entry(role.clone()).or_default().push(id.0);
        }
        if registry_active {
            announces.push(AnnouncePlan {
                name: a.name.clone(),
                owner_prefix: id.node_prefix(),
                service_id: id.local_id(),
                roles: a.provides.clone(),
            });
        }
    }
}

/// Auto-heartbeat: periodic `heartbeat(name)` invokes for
/// every announced service so the registry's `last_seen`
/// stays current. Only fires when (a) we have a registry,
/// (b) something to ping, (c) we're in long-lived mode, and
/// (d) the operator hasn't disabled it via interval=0.
fn spawn_heartbeat(
    manifest: &Manifest,
    node: &VosNode,
    announces: &[AnnouncePlan],
    registry_active: bool,
    networked: bool,
) -> Option<std::thread::JoinHandle<()>> {
    if !(registry_active && !announces.is_empty() && networked) {
        return None;
    }
    let interval_secs = manifest.heartbeat_interval_secs.unwrap_or(30);
    if interval_secs == 0 {
        return None;
    }
    let names: Vec<String> = announces.iter().map(|a| a.name.clone()).collect();
    let handle = node.invoke_handle();
    let interval = Duration::from_secs(interval_secs);
    eprintln!(
        "vosx: auto-heartbeat every {interval_secs}s for {} service(s)",
        names.len(),
    );
    Some(std::thread::spawn(move || heartbeat_loop(handle, names, interval)))
}
