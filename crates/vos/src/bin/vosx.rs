//! `vosx` — JAM-aligned PVM executor.

use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vos::init::{InitArgs, InitValue};
use vos::runtime::VosRuntime;

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Program or manifest to run (auto-detected by extension)
    file: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ConsistencyArg {
    Ephemeral,
    Local,
    Crdt,
}

impl From<ConsistencyArg> for vos::node::Consistency {
    fn from(a: ConsistencyArg) -> Self {
        match a {
            ConsistencyArg::Ephemeral => vos::node::Consistency::Ephemeral,
            ConsistencyArg::Local => vos::node::Consistency::Local,
            ConsistencyArg::Crdt => vos::node::Consistency::Crdt,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run a PVM/ELF program
    Run {
        program: PathBuf,
        /// Deliver file contents as a FETCH work item (repeatable)
        #[arg(long, value_name = "FILE")]
        payload: Vec<PathBuf>,
        /// Deliver hex-encoded bytes as a FETCH work item (repeatable)
        #[arg(long, value_name = "HEX")]
        hex: Vec<String>,
        /// Set gas limit
        #[arg(long, default_value_t = 100_000_000)]
        gas: u64,
    },
    /// Run multiple agents concurrently
    Node {
        programs: Vec<PathBuf>,
        /// Load a registry service at ServiceId(0)
        #[arg(long, value_name = "FILE")]
        registry: Option<PathBuf>,
        /// Load native worker plugins. Optional init args after a colon:
        ///   --worker libfoo.so
        ///   --worker libfoo.so:key=hello,n=42
        ///
        /// Values are auto-typed: integers → U64, true/false → Bool,
        /// everything else → Str. For explicit types use TOML manifest.
        #[arg(long, value_name = "FILE[:KEY=VAL,...]")]
        worker: Vec<String>,
        /// Data directory for state persistence. Workers are stored in
        /// `{data_dir}/workers/{name}.redb`. Default: no persistence.
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
        /// Replication / persistence semantics for the PVM agents.
        ///   ephemeral — in-memory only (default)
        ///   local     — redb-backed, no replication
        ///   crdt      — merkle-CRDT: state + DAG + roots committed
        ///               atomically, effect logs recorded for sync
        #[arg(long, value_name = "MODE", default_value = "ephemeral")]
        consistency: ConsistencyArg,
    },
    /// Start the space defined by a manifest. With no path, looks
    /// for `space.toml` in the current directory.
    Start {
        manifest: Option<PathBuf>,
        /// Override the data directory (default: `data`). Per-actor
        /// persistence is gated by each actor's `consistency` field.
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence entirely (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
        /// libp2p multiaddr to listen on. Combines with the
        /// manifest's `[node].listen`. Inert when vosx was built
        /// without the `network` feature. Example:
        ///   --listen /ip4/0.0.0.0/tcp/4001
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
    },
    /// List actors in a manifest
    List {
        manifest: Option<PathBuf>,
    },
    /// Resolve a service name (or accept a `0x…` ServiceId) and
    /// invoke a typed message on it. The CLI joins the
    /// manifest's hyperspace as a transient peer, looks the
    /// name up via the registry actor like any other service,
    /// then forwards the call. Use this to drive any actor —
    /// the registry included (`vosx invoke registry list`).
    Invoke {
        /// Service name (looked up in registry) or a literal
        /// `0xHEX` ServiceId.
        target: String,
        /// Message name (e.g. `inc`, `get`, `lookup`).
        msg: String,
        /// Repeatable: `--arg key=value`. Auto-typed: integer
        /// → u64, `true`/`false` → bool, everything else → str.
        #[arg(long, value_name = "KEY=VALUE")]
        arg: Vec<String>,
        /// Manifest path. Defaults to `space.toml`.
        manifest: Option<PathBuf>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Seconds to wait for registry sync before resolving
        /// the target name. Ignored when target is `0x…`.
        #[arg(long, default_value_t = 3)]
        sync_timeout: u64,
    },
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Run { program, payload, hex, gas }) => {
            cmd_run(&program, &payload, &hex, gas);
        }
        Some(Command::Node { programs, registry, worker, data_dir, no_persist, consistency }) => {
            let dir = if no_persist { None } else { data_dir.as_deref() };
            cmd_node(&programs, registry.as_deref(), &worker, dir, consistency.into());
        }


        Some(Command::Start { manifest, data_dir, no_persist, listen, connect }) => {
            let (m, dir) = manifest_from(manifest);
            cmd_start(&m, &dir, data_dir.as_deref(), no_persist, &listen, &connect);
        }
        Some(Command::List { manifest }) => {
            let (m, dir) = manifest_from(manifest);
            cmd_list(&m, &dir);
        }
        Some(Command::Invoke { target, msg, arg, manifest, connect, sync_timeout }) => {
            let (m, dir) = manifest_from(manifest);
            cmd_invoke(&m, &dir, &target, &msg, &arg, &connect, sync_timeout);
        }
        None if cli.file.as_ref().is_some_and(|p| !is_manifest(p)) => {
            cmd_run(cli.file.as_ref().unwrap(), &[], &[], 100_000_000);
        }
        None => {
            let (m, dir) = manifest_from(cli.file);
            cmd_start(&m, &dir, Some(Path::new("data")), false, &[], &[]);
        }
    }
}

// ── Commands ─────────────────────────────────────────────────────────

fn cmd_run(program: &Path, payloads: &[PathBuf], hex: &[String], gas: u64) {
    let blob = load_blob(program);
    let mut rt = VosRuntime::with_gas_config(vos::runtime::GasConfig {
        refine_gas: gas, accumulate_gas_max: gas, accumulate_gas_default: gas,
    });

    let idx = rt.register_service_blob(blob);
    let id = rt.register_service(idx);
    eprintln!("vosx: loaded '{}' as {id:?}", program.display());

    let mut items: Vec<Vec<u8>> = Vec::new();
    for p in payloads {
        items.push(if p.as_os_str() == "-" { read_stdin() } else { load_file(p) });
    }
    for h in hex {
        items.push(hex_decode(h).unwrap_or_else(|| die(&format!("invalid hex '{h}'"))));
    }
    if items.is_empty() { items.push(Vec::new()); }

    for item in items { rt.send_to(id, item); }

    eprintln!("vosx: running...\n");
    rt.run_blocking();
    exit_with_status(rt.panics);
}

fn cmd_node(
    programs: &[PathBuf],
    registry: Option<&Path>,
    workers: &[String],
    data_dir: Option<&Path>,
    consistency: vos::node::Consistency,
) {
    use vos::node::{AgentConfig, WorkerConfig, VosNode};
    use vos::value::Args;

    let mut node = VosNode::new();

    // Register workers first so PVM agents can invoke them.
    for spec in workers {
        let (path_str, args_str) = match spec.split_once(':') {
            Some((p, a)) => (p, Some(a)),
            None => (spec.as_str(), None),
        };
        let path = PathBuf::from(path_str);

        let mut config = match args_str {
            Some(s) if !s.is_empty() => {
                let mut args = Args::new();
                for kv in s.split(',') {
                    let Some((k, v)) = kv.split_once('=') else {
                        die(&format!("invalid worker arg '{kv}', expected KEY=VALUE"));
                    };
                    args = args.with(k, parse_cli_value(v));
                }
                WorkerConfig::with_args(path.clone(), &args)
            }
            _ => WorkerConfig::new(path.clone()),
        };

        if let Some(dir) = data_dir {
            config = config.persist(dir);
        }

        let id = node.register_worker(config);
        eprintln!("vosx: worker '{}' as {id:?}", path.display());
    }

    // Helper: apply shared consistency + data_dir to an AgentConfig.
    let mk_agent = |blob: Vec<u8>| -> AgentConfig {
        let mut c = AgentConfig::new(blob).with_consistency(consistency);
        if let Some(dir) = data_dir {
            c = c.persist(dir);
        }
        c
    };

    // Load registry at ServiceId(0) if specified
    if let Some(reg_path) = registry {
        let id = node.register(mk_agent(load_blob(reg_path)));
        eprintln!("vosx: registry '{}' as {id}", reg_path.display());
    }

    for path in programs {
        let id = node.register(mk_agent(load_blob(path)));
        eprintln!("vosx: registered '{}' as {id:?}", path.display());
    }

    let total = programs.len() + workers.len();
    eprintln!("vosx: running {total} service(s) ({} PVM + {} worker)...\n",
        programs.len(), workers.len());
    node.run();

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

fn cmd_list(manifest: &Manifest, dir: &Path) {
    println!("space: {}", manifest.space);
    if let Some(v) = &manifest.version {
        println!("  version: {v}");
    }
    if let Some(hs) = &manifest.hyperspace {
        println!("  hyperspace: {hs}");
    }
    println!();

    for a in &manifest.agent {
        let role = format!(
            "agent {:?}{}",
            a.consistency,
            if a.provides.is_empty() {
                String::new()
            } else {
                format!(" provides={:?}", a.provides)
            }
        );
        let path = resolve_entry_path_for_listing(&a.name, &a.path, &a.service, dir);
        print_actor_meta(&a.name, &path, &role);

        for child in &a.actors {
            let role = format!(
                "actor (child of {}){}",
                a.name,
                if child.provides.is_empty() {
                    String::new()
                } else {
                    format!(" provides={:?}", child.provides)
                }
            );
            let path = resolve_entry_path_for_listing(&child.name, &child.path, &child.service, dir);
            print_actor_meta(&child.name, &path, &role);
        }
    }

    for w in &manifest.worker {
        let path = resolve_entry_path_for_listing(&w.name, &w.path, &w.service, dir);
        let role_tag = if w.provides.is_empty() {
            String::new()
        } else {
            format!(" provides={:?}", w.provides)
        };
        if path.exists() {
            println!("  {} (worker{role_tag}) — {}", w.name, path.display());
        } else {
            println!("  {} (worker{role_tag}) — not built ({})", w.name, path.display());
        }
    }
}

/// Like `resolve_entry_path` but for `vosx list` — doesn't `die` on
/// `service` since list is a read-only inspection command.
fn resolve_entry_path_for_listing(
    name: &str,
    path: &Option<PathBuf>,
    service: &Option<String>,
    dir: &Path,
) -> PathBuf {
    if let Some(p) = path {
        dir.join(p)
    } else if let Some(s) = service {
        // Display-only placeholder.
        PathBuf::from(format!("<service: {s}>"))
    } else {
        PathBuf::from(format!("<unspecified for '{name}'>"))
    }
}

/// Run the space defined by `manifest`.
///
/// Registration order:
/// 1. All `[[worker]]` entries — their IDs become resolvable for
///    everything below.
/// 2. For each `[[agent]]`, its `actors` (child actors) first so the
///    agent's own `init` can reference them by name, then the agent
///    itself.
///
/// String values in `init` tables that match a previously-declared
/// name resolve to that peer's ServiceId. Forward references error
/// out cleanly. Cross-agent actor refs require the target agent's
/// children to be registered before the referring agent.
fn cmd_start(
    manifest: &Manifest,
    dir: &Path,
    data_dir_cli: Option<&Path>,
    no_persist: bool,
    listen_cli: &[String],
    connect_cli: &[String],
) {
    use vos::node::{AgentConfig, VosNode, WorkerConfig};
    use vos::value::Args;

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

    // ── Network startup ─────────────────────────────────────────────
    //
    // Combine CLI flags with manifest [node].listen. If anything to
    // listen on or connect to is configured, start the libp2p
    // network. Today this just establishes the pipe — peer
    // connections are logged but no actor traffic flows yet.
    #[cfg(feature = "network")]
    let network = start_network_if_needed(manifest, data_dir.as_deref(), listen_cli, connect_cli);
    #[cfg(not(feature = "network"))]
    {
        if !listen_cli.is_empty() || !connect_cli.is_empty()
            || !manifest.node.listen.is_empty()
        {
            eprintln!(
                "vosx: warning: --listen / --connect / [node].listen ignored \
                 (vosx was built without the `network` feature)",
            );
        }
    }

    // Sanity: no two declarations share a name across agents,
    // child actors, and workers.
    {
        let mut seen = BTreeMap::<String, &str>::new();
        let mut check = |name: &str, kind: &'static str| {
            if let Some(prev) = seen.insert(name.to_string(), kind) {
                die(&format!(
                    "duplicate name '{name}' in manifest (already used as {prev})",
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

    // Use the network's prefix (when present) so all locally-
    // allocated ServiceIds carry the right high 16 bits. Without a
    // network we use prefix 0 — matches the pre-networking
    // single-process behaviour.
    #[cfg(feature = "network")]
    let mut node = match &network {
        Some(net) => VosNode::with_prefix(net.local_prefix()),
        None => VosNode::new(),
    };
    #[cfg(not(feature = "network"))]
    let mut node = VosNode::new();
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    // role → list of ServiceIds providing it. Init values prefixed
    // with '@' resolve through this map (e.g. peer = "@registry").
    // Multiple providers of the same role yield an ambiguity error;
    // dynamic role lookup at runtime is a future feature alongside
    // the registry actor.
    let mut provides_map: BTreeMap<String, Vec<u32>> = BTreeMap::new();

    // ── Hyperspace registry (phase-2 auto-spawn) ────────────────────
    //
    // When `hyperspace = "..."` is declared, vosx spins up a CRDT
    // replica of the registry actor at the well-known
    // `ServiceId::REGISTRY`, derives the replication group from
    // `blake2b("vos-registry/v1" || hyperspace_name)`, and queues
    // up announcements for every declared agent so the local
    // replica (and via cycles 1–8, every replica in the
    // hyperspace) sees them. `registry_blob` points at the actor
    // ELF; future cycles will embed it.
    let registry_active = if let Some(hyperspace_name) = &manifest.hyperspace {
        let blob_path = match &manifest.registry_blob {
            Some(p) => dir.join(p),
            None => die(&format!(
                "manifest declares hyperspace='{hyperspace_name}' but no \
                 `registry_blob` path; phase-2 vosx needs the registry \
                 actor's elf until embedding lands",
            )),
        };
        let elf_data = load_file(&blob_path);
        let blob = load_blob(&blob_path);
        let rep_id = registry::replication_id(hyperspace_name);
        let mut cfg = vos::node::AgentConfig::new(blob)
            .with_consistency(vos::node::Consistency::Crdt)
            .with_replication_id(rep_id);
        if let Some(d) = &state_dir {
            cfg = cfg.persist(d);
        }
        let id = node.register_at_id(cfg, vos::abi::service::ServiceId::REGISTRY);
        eprintln!(
            "vosx: hyperspace='{hyperspace_name}' registry as {id} (rep_id={})",
            hex32(&rep_id),
        );
        let _ = elf_data;
        true
    } else {
        false
    };

    // Collected at registration; flushed as `announce` invokes
    // after attach_network so the local registry sees every
    // locally-declared agent (and replicates them outward).
    let mut announces: Vec<AnnouncePlan> = Vec::new();

    // ── Workers ─────────────────────────────────────────────────────
    for w in &manifest.worker {
        let path = resolve_entry_path(&w.name, &w.path, &w.service, dir);
        let mut cfg = if w.init.is_empty() {
            WorkerConfig::new(path)
        } else {
            let mut args = Args::new();
            for (k, v) in &w.init {
                args = args.with(k, toml_to_value(v, &name_ids, &provides_map));
            }
            WorkerConfig::with_args(path, &args)
        };
        if let Some(d) = &state_dir {
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

    // ── Agents and their child actors ──────────────────────────────
    for a in &manifest.agent {
        // 1. Child actors first.
        for child in &a.actors {
            let path = resolve_entry_path(&child.name, &child.path, &child.service, dir);
            let elf_data = load_file(&path);
            let blob = load_blob(&path);

            // Child actors inherit the agent's consistency by
            // default. Override would land as a per-actor field if
            // we ever need it; for now they're all the agent's tier.
            let mut cfg = AgentConfig::new(blob.clone()).with_consistency(a.consistency.into());
            if let Some(d) = &state_dir {
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
            cfg = apply_init(cfg, &child.init, &elf_data, &name_ids, &provides_map);
            if !child.on_start.is_empty() {
                let payloads = encode_on_start(&child.name, &child.on_start, &elf_data, &name_ids, &provides_map);
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

        // 2. Agent itself.
        let path = resolve_entry_path(&a.name, &a.path, &a.service, dir);
        let elf_data = load_file(&path);
        let blob = load_blob(&path);

        let mut cfg = AgentConfig::new(blob.clone()).with_consistency(a.consistency.into());
        if let Some(d) = &state_dir {
            cfg = cfg.persist(d);
        }
        if a.consistency == ConsistencyDef::Crdt {
            if let Some(rep_id) = resolve_replication_id(
                &a.name,
                a.replication_id.as_deref(),
                &blob,
            ) {
                cfg = cfg.with_replication_id(rep_id);
            }
        }
        cfg = apply_init(cfg, &a.init, &elf_data, &name_ids, &provides_map);
        if !a.on_start.is_empty() {
            let payloads = encode_on_start(&a.name, &a.on_start, &elf_data, &name_ids, &provides_map);
            cfg = cfg.with_init_payloads(payloads);
        }

        let id = node.register(cfg);
        let role_tag = format_provides(&a.provides);
        eprintln!(
            "vosx: agent '{}' as {id} ({:?}){role_tag}",
            a.name, a.consistency,
        );
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

    // Hand the network off to the node, which spawns a bridge
    // thread for inbound Tells and starts forwarding non-local
    // routes over the wire. After this `network` is owned by
    // `node` — both die together at collect time.
    #[cfg(feature = "network")]
    let networked = network.is_some();
    #[cfg(feature = "network")]
    if let Some(net) = network {
        node.attach_network(net);
    }
    #[cfg(not(feature = "network"))]
    let networked = false;

    // Flush registry announces. Each invoke goes through
    // invoke_routes locally (the registry replica lives on this
    // node at ServiceId::REGISTRY), no network hop needed; the
    // CRDT layer handles outward replication.
    if registry_active && !announces.is_empty() {
        flush_registry_announces(&node, &announces);
    }

    // Auto-heartbeat: periodic `heartbeat(name)` invokes for
    // every announced service so the registry's `last_seen`
    // stays current. Only fires when (a) we have a registry,
    // (b) something to ping, (c) we're in long-lived mode, and
    // (d) the operator hasn't disabled it via interval=0. The
    // thread runs alongside `run_forever`, polling its own
    // `InvokeHandle`, and stops when the node signals shutdown.
    let heartbeat_thread = if registry_active && !announces.is_empty() && networked {
        let interval_secs = manifest.heartbeat_interval_secs.unwrap_or(30);
        if interval_secs == 0 {
            None
        } else {
            let names: Vec<String> = announces.iter().map(|a| a.name.clone()).collect();
            let handle = node.invoke_handle();
            let interval = std::time::Duration::from_secs(interval_secs);
            eprintln!(
                "vosx: auto-heartbeat every {}s for {} service(s)",
                interval_secs,
                names.len(),
            );
            Some(std::thread::spawn(move || heartbeat_loop(handle, names, interval)))
        }
    } else {
        None
    };

    eprintln!("vosx: running space '{}'...\n", manifest.space);
    if networked {
        eprintln!("vosx: networking on — running until shutdown (Ctrl-C)");
        node.run_forever();
    } else {
        node.run();
    }

    if let Some(h) = heartbeat_thread {
        // run_forever / run already flipped the shutdown flag.
        // Join so the thread doesn't outlive us.
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

/// Pending registry announce: vosx sends these to the local
/// `ServiceId::REGISTRY` after `attach_network`. One per
/// declared agent / child actor when `hyperspace` is set.
struct AnnouncePlan {
    name: String,
    owner_prefix: u16,
    service_id: u16,
    roles: Vec<String>,
}

// ── `vosx invoke` (transient query node) ───────────────────────────
//
// Spin up an ephemeral, non-persisting VosNode that joins the
// manifest's hyperspace, wait briefly for CRDT sync to populate
// the local registry replica from peers, resolve the target
// name, fire the invoke, and exit. No data dir, no long-lived
// state — the node is gone after the command returns.
//
// Name resolution uses the registry actor like any other caller
// would: invoke `lookup(name)` at `ServiceId::REGISTRY`, decode
// the rkyv-encoded `RegistryEntry` reply. The wire encoding is
// inlined here rather than pulled from `registry-client`,
// because vos's binary can't depend on the client crate
// (`registry-client` already depends on `vos`).

/// Invoke the well-known registry actor's `lookup(name)` and
/// decode the rkyv-encoded `RegistryEntry` reply. Used both by
/// `vosx invoke <NAME>` for name resolution and by
/// `with_query_node` to detect when CRDT sync has populated the
/// local replica.
#[cfg(feature = "network")]
fn registry_lookup(node: &vos::node::VosNode, name: &str) -> Option<registry::RegistryEntry> {
    use vos::value::TAG_DYNAMIC;
    use vos::Encode;
    let m = vos::value::Msg::new("lookup").with("name", name);
    let encoded = m.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let bytes = node.invoke_with_timeout(
        vos::abi::service::ServiceId::REGISTRY,
        payload,
        std::time::Duration::from_secs(5),
    )?;
    let value: vos::value::Value = vos::Decode::decode(&bytes);
    match value {
        vos::value::Value::Bytes(b) if !b.is_empty() => {
            registry::decode_archived::<registry::RegistryEntry>(&b)
        }
        _ => None,
    }
}

#[cfg(feature = "network")]
fn cmd_invoke(
    manifest: &Manifest,
    dir: &Path,
    target_str: &str,
    msg_name: &str,
    args: &[String],
    connect: &[String],
    sync_timeout: u64,
) {
    use vos::abi::service::ServiceId;
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;

    // Argument parsing first so an obvious typo fails fast,
    // before we waste time spinning up the network.
    let mut msg = Msg::new(msg_name);
    for a in args {
        let (k, v) = a.split_once('=').unwrap_or_else(|| {
            die(&format!("--arg '{a}' must be 'key=value'"));
        });
        msg = match parse_arg_value(v) {
            ParsedArg::U32(n) => msg.with(k, n),
            ParsedArg::U64(n) => msg.with(k, n),
            ParsedArg::Bool(b) => msg.with(k, b),
            ParsedArg::Str(s) => msg.with(k, s),
        };
    }

    with_query_node(manifest, dir, connect, sync_timeout, |node| {
        let target = if let Some(hex) = target_str.strip_prefix("0x") {
            let raw = u32::from_str_radix(hex, 16)
                .unwrap_or_else(|e| die(&format!("invalid 0x ServiceId '{target_str}': {e}")));
            ServiceId(raw)
        } else {
            match registry_lookup(node, target_str) {
                Some(e) => ServiceId(e.full_service_id()),
                None => {
                    eprintln!("'{target_str}' not registered");
                    std::process::exit(1);
                }
            }
        };
        eprintln!("vosx: invoking {msg_name} on {target}");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let reply = match node.invoke_with_timeout(
            target, payload, std::time::Duration::from_secs(10),
        ) {
            Some(r) => r,
            None => {
                eprintln!("invoke: no reply (target unreachable or timed out)");
                std::process::exit(2);
            }
        };
        // Unit-returning handlers reply with zero bytes — print
        // a placeholder so the user sees the call completed.
        if reply.is_empty() {
            println!("()");
        } else {
            let value: vos::value::Value = vos::Decode::decode(&reply);
            println!("{value:?}");
        }
    });
}

#[cfg(not(feature = "network"))]
fn cmd_invoke(
    _manifest: &Manifest,
    _dir: &Path,
    _target_str: &str,
    _msg_name: &str,
    _args: &[String],
    _connect: &[String],
    _sync_timeout: u64,
) {
    die("`vosx invoke` requires the `network` feature");
}

#[cfg(feature = "network")]
enum ParsedArg { U32(u32), U64(u64), Bool(bool), Str(String) }

/// Parse a `--arg key=value` value. Optional `type:` prefix
/// pins the wire type (`u32:42`, `u64:42`, `bool:true`,
/// `str:42`); without one we autotype: `true`/`false` → bool,
/// integer → u64, anything else → string. Use a prefix when
/// the actor's handler takes a narrower integer type — `u64`
/// will silently no-op against a `u32` handler.
#[cfg(feature = "network")]
fn parse_arg_value(v: &str) -> ParsedArg {
    if let Some((ty, rest)) = v.split_once(':') {
        match ty {
            "u32" => return ParsedArg::U32(rest.parse::<u32>()
                .unwrap_or_else(|e| die(&format!("--arg u32:{rest}: {e}")))),
            "u16" | "u8" => return ParsedArg::U32(rest.parse::<u32>()
                .unwrap_or_else(|e| die(&format!("--arg {ty}:{rest}: {e}")))),
            "u64" => return ParsedArg::U64(rest.parse::<u64>()
                .unwrap_or_else(|e| die(&format!("--arg u64:{rest}: {e}")))),
            "bool" => return ParsedArg::Bool(rest.parse::<bool>()
                .unwrap_or_else(|e| die(&format!("--arg bool:{rest}: {e}")))),
            "str" => return ParsedArg::Str(rest.to_string()),
            _ => {} // unknown prefix → fall through to autotype
        }
    }
    if v.eq_ignore_ascii_case("true") { return ParsedArg::Bool(true); }
    if v.eq_ignore_ascii_case("false") { return ParsedArg::Bool(false); }
    if let Ok(n) = v.parse::<u64>() { return ParsedArg::U64(n); }
    ParsedArg::Str(v.to_string())
}

/// Spin up a transient ephemeral node that joins the manifest's
/// hyperspace, wait briefly for sync, run `f` against it, then
/// shut down. Used by `vosx registry` and `vosx invoke`.
///
/// `sync_timeout_secs` is the upper bound; we exit early once
/// the registry has at least one entry (or any peer has
/// completed Hello), whichever happens first.
#[cfg(feature = "network")]
fn with_query_node(
    manifest: &Manifest,
    dir: &Path,
    connect: &[String],
    sync_timeout_secs: u64,
    f: impl FnOnce(&vos::node::VosNode),
) {
    let hyperspace = manifest.hyperspace.as_deref().unwrap_or_else(|| {
        die("manifest does not declare a `hyperspace`; nothing to query");
    });
    let blob_path = manifest.registry_blob.as_ref().map(|p| dir.join(p))
        .unwrap_or_else(|| die("manifest must set `registry_blob` for query commands"));
    let blob = load_blob(&blob_path);
    let rep_id = registry::replication_id(hyperspace);

    // Always listen on a random loopback port — the CLI is a
    // transient peer; a fixed port would clash with running
    // instances. Bootstrap from --connect and from manifest.
    use std::str::FromStr;
    let listen: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
    let parse = |s: &str| -> Option<libp2p::Multiaddr> {
        match libp2p::Multiaddr::from_str(s) {
            Ok(a) => Some(a),
            Err(e) => { eprintln!("vosx: ignoring bad multiaddr '{s}': {e}"); None }
        }
    };
    let mut bootstrap: Vec<libp2p::Multiaddr> = connect.iter().filter_map(|s| parse(s)).collect();
    bootstrap.extend(manifest.node.listen.iter().filter_map(|s| parse(s)));

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_prefix = vos::network::derive_node_prefix(
        &libp2p::PeerId::from(keypair.public()),
    );

    let net = vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen: vec![listen],
        bootstrap,
    });

    // CRDT replicas require a `data_dir` on disk for their redb;
    // for the transient CLI we hand them a one-shot tempdir that
    // we wipe on the way out. The sync-from-peers path doesn't
    // care that the dir is fresh — it pulls the DAG nodes it
    // needs over libp2p and commits them locally.
    let temp_root = std::env::temp_dir().join(format!(
        "vosx-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    if let Err(e) = std::fs::create_dir_all(&temp_root) {
        die(&format!("creating tempdir {}: {e}", temp_root.display()));
    }

    let mut node = vos::node::VosNode::with_prefix(local_prefix);
    let _ = node.register_at_id(
        vos::node::AgentConfig::new(blob)
            .with_consistency(vos::node::Consistency::Crdt)
            .persist(&temp_root)
            .with_replication_id(rep_id),
        vos::abi::service::ServiceId::REGISTRY,
    );
    node.attach_network(net);
    let net_arc = node.network().expect("network was just attached");

    // Wait for sync. Hello-handshake is fast (tens of ms), but
    // pulling the DAG and replaying takes a couple of sync
    // intervals (~250ms each). We early-exit only when the
    // registry actually has entries — `has_peers` alone fires
    // before any state has flowed.
    // Sync warmup: wait for at least one peer to appear, then
    // give the CRDT layer a fixed window to pull the registry
    // DAG. Hello-handshake is fast (tens of ms); fetching and
    // applying logs takes a couple of sync intervals (250ms
    // each). Whole budget is `sync_timeout_secs`.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(sync_timeout_secs);
    while std::time::Instant::now() < deadline && net_arc.connected_peers().is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Allow time for CRDT replay after the first peer appears,
    // bounded by the remaining budget.
    let post_peer_window = std::time::Duration::from_millis(750);
    let drain_until = (std::time::Instant::now() + post_peer_window).min(deadline);
    while std::time::Instant::now() < drain_until {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    f(&node);

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&temp_root);
}

/// Background heartbeat loop. Each tick walks `names` and fires
/// a `heartbeat(name)` invoke at `ServiceId::REGISTRY` through
/// `handle`. Exits when the owning node flips its shutdown
/// flag. Replies are ignored — `heartbeat` doesn't return
/// anything meaningful, and the next tick recovers from any
/// transient miss.
fn heartbeat_loop(
    handle: vos::node::InvokeHandle,
    names: Vec<String>,
    interval: std::time::Duration,
) {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    // Sleep up front so we don't double-announce immediately
    // after the initial flush.
    let tick = std::time::Duration::from_millis(100);
    let mut waited = std::time::Duration::ZERO;
    loop {
        // Sleep in small slices so shutdown is observed
        // promptly without blocking the join at exit.
        while waited < interval {
            if handle.is_shutting_down() { return; }
            std::thread::sleep(tick);
            waited += tick;
        }
        waited = std::time::Duration::ZERO;
        for name in &names {
            if handle.is_shutting_down() { return; }
            let m = Msg::new("heartbeat").with("name", name.as_str());
            let encoded = m.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            let _ = handle.invoke_with_timeout(
                vos::abi::service::ServiceId::REGISTRY,
                payload,
                std::time::Duration::from_secs(2),
            );
        }
    }
}

/// Send an `announce(...)` invoke for every plan to the local
/// registry. Inlines the wire encoding rather than depending on
/// `registry::Client` to avoid a vos→registry→vos build cycle.
fn flush_registry_announces(node: &vos::node::VosNode, plans: &[AnnouncePlan]) {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    for plan in plans {
        let m = Msg::new("announce")
            .with("name", plan.name.clone())
            .with("owner_prefix", plan.owner_prefix as u32)
            .with("service_id", plan.service_id as u32)
            .with("roles", plan.roles.clone());
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let reply = node.invoke_with_timeout(
            vos::abi::service::ServiceId::REGISTRY,
            payload,
            std::time::Duration::from_secs(2),
        );
        if reply.is_none() {
            eprintln!(
                "vosx: warning: registry announce for '{}' returned no reply",
                plan.name,
            );
        } else {
            eprintln!("vosx: registered '{}' in registry", plan.name);
        }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn format_provides(provides: &[String]) -> String {
    if provides.is_empty() {
        String::new()
    } else {
        format!(" provides={provides:?}")
    }
}

/// Translate the manifest's `replication_id` value into the
/// 32-byte handle [`AgentConfig::with_replication_id`] expects.
///
/// - `None` or `Some("auto")` — derive from
///   `blake2b(name || 0 || blob)`. Two replicas of the same code
///   under the same name auto-share a group, no manifest
///   coordination needed.
/// - `Some("off")` — explicitly opt out of replication; CRDT
///   actor's DAG stays purely local.
/// - `Some(hex)` — 64-char hex (`[0-9a-fA-F]{64}`) treated as an
///   explicit 32-byte id. Useful for cross-cluster pinning where
///   the auto-derived id won't match because operators ship
///   different blobs of the "same" actor.
///
/// Anything else is a manifest error.
fn resolve_replication_id(name: &str, spec: Option<&str>, blob: &[u8]) -> Option<[u8; 32]> {
    match spec.map(str::trim) {
        Some("off") => None,
        None | Some("") | Some("auto") => Some(auto_replication_id(name, blob)),
        Some(hex) => match decode_hex_32(hex) {
            Some(arr) => Some(arr),
            None => die(&format!(
                "'{name}': replication_id must be \"auto\", \"off\", or 64 hex chars; got {hex:?}",
            )),
        },
    }
}

/// Encode the manifest's `on_start` entries as TAG_DYNAMIC +
/// rkyv-encoded `Msg` payloads — the same wire shape
/// `VosNode::invoke` and `ctx.tell` use. The agent thread
/// receives these as initial inbox messages and dispatches them
/// before reading from the inbox channel.
///
/// Argument types are looked up from the actor's `MessageMeta`
/// so a TOML integer sent to a `u32` parameter lands as
/// `Value::U32` (not the default `Value::U64`) — without that,
/// the macro's `from_dynamic` fails to extract the field and
/// dispatch silently skips.
fn encode_on_start(
    agent_name: &str,
    entries: &[OnStartMsg],
    elf_data: &[u8],
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> Vec<Vec<u8>> {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    let meta = vos::metadata::from_elf(elf_data);
    let mut out = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let mut m = Msg::new(entry.msg.clone());
        let handler_meta = meta
            .as_ref()
            .and_then(|am| am.messages.iter().find(|h| h.name.as_str() == entry.msg.as_str()));
        for (k, v) in &entry.args {
            // If the handler advertises a typed parameter, use it
            // to coerce the TOML scalar into the right `Value`
            // variant; otherwise fall back to the inference
            // `toml_to_value` does.
            let typed = handler_meta
                .and_then(|h| h.fields.iter().find(|f| f.name.as_str() == k.as_str()))
                .and_then(|f| typed_value(v, f.ty.as_str()));
            let value = typed.unwrap_or_else(|| toml_to_value(v, name_ids, provides_map));
            m = m.with(k.clone(), value);
        }
        let encoded = m.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        eprintln!(
            "vosx: on_start[{idx}] '{}' -> {}({})",
            agent_name,
            entry.msg,
            entry.args.iter().map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>().join(", "),
        );
        out.push(payload);
        // Suppress unused warning when on_start carries no args.
        let _ = (name_ids, provides_map);
    }
    out
}

/// Coerce a TOML scalar to a typed `Value` matching the handler's
/// declared parameter type. Returns `None` for unhandled
/// combinations so the caller can fall back to inference.
fn typed_value(val: &toml::Value, ty: &str) -> Option<vos::value::Value> {
    use vos::value::Value;
    match (val, ty.replace(' ', "").as_str()) {
        (toml::Value::Integer(n), "u32") => Some(Value::U32(*n as u32)),
        (toml::Value::Integer(n), "u64") => Some(Value::U64(*n as u64)),
        (toml::Value::Integer(n), "i64") => Some(Value::I64(*n)),
        (toml::Value::Integer(n), "i32") => Some(Value::I32(*n as i32)),
        (toml::Value::Integer(n), "u16") => Some(Value::U16(*n as u16)),
        (toml::Value::Integer(n), "u8") => Some(Value::U8(*n as u8)),
        (toml::Value::Boolean(b), "bool") => Some(Value::Bool(*b)),
        (toml::Value::String(s), "String") => Some(Value::Str(s.clone())),
        _ => None,
    }
}

fn auto_replication_id(name: &str, blob: &[u8]) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(name.as_bytes());
    h.update(&[0u8]);
    h.update(blob);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn apply_init(
    mut cfg: vos::node::AgentConfig,
    init: &BTreeMap<String, toml::Value>,
    elf_data: &[u8],
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> vos::node::AgentConfig {
    if init.is_empty() {
        return cfg;
    }
    let meta = vos::metadata::from_elf(elf_data);
    let mut args = InitArgs::new();
    for (key, val) in init {
        let ty = meta
            .as_ref()
            .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
            .map(|f| f.ty.as_str())
            .unwrap_or("String");
        args = args.with(key, toml_to_init_value(val, ty, name_ids, provides_map));
    }
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    cfg = cfg.with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded.to_vec())]);
    cfg
}

// ── Manifest ─────────────────────────────────────────────────────────
//
// One vosx instance runs one space. Space-level properties live at
// the TOML root (no `[space]` wrapper). `[[agent]]` lists the PVM
// services running here; each agent can host child actors inline.
// `[[worker]]` lists native plugins (.so / .dylib) — the I/O surface
// of the space. `[node]` is the per-instance section (libp2p
// identity, listen addresses, data dir).
//
// Schema overview:
//
//   space      = "demo"                # required
//   version    = "0.1.0"               # optional, the space's own version
//   hyperspace = "main-hub"            # optional; inherits registry + peers
//
//   [[agent]]
//     name = "scheduler"
//     path | service = ...             # exactly one
//     consistency = "ephemeral" | "local" | "crdt"
//     provides = ["role-1", ...]
//     init = { ... }
//     actors = [ { name = "ledger", path = "...", init = { ... } }, ... ]
//
//   [[worker]]
//     name = "rate-oracle"
//     path | service = ...
//     provides = ["rates"]
//     init = { ... }
//
//   [node]
//     identity = "auto"
//     listen   = ["/ip4/0.0.0.0/tcp/4001"]
//     data_dir = "./data"

#[derive(Deserialize)]
struct Manifest {
    space: String,
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
    /// Optional hyperspace this space joins. When set, vosx
    /// auto-spawns a registry replica at `ServiceId::REGISTRY`
    /// using `registry_blob` as the actor binary, and registers
    /// every declared agent in it on startup. The replication
    /// group is `blake2b("vos-registry/v1" || hyperspace_name)`
    /// — every node in the same hyperspace converges.
    #[serde(default)]
    hyperspace: Option<String>,
    /// Path to the registry actor's `.elf`. Required when
    /// `hyperspace` is set. Resolved relative to the manifest
    /// directory. Future: vosx will embed the actor itself and
    /// this field becomes a release-pinned override.
    #[serde(default)]
    registry_blob: Option<PathBuf>,
    /// How often vosx pings each auto-announced service via
    /// `heartbeat(name)` so the registry's `last_seen` stays
    /// current. `None` (the default) → 30s. Set to 0 to disable
    /// auto-heartbeat. Only fires when `hyperspace` is set and
    /// the node runs in long-lived (`run_forever`) mode.
    #[serde(default)]
    heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    agent: Vec<AgentDef>,
    #[serde(default)]
    worker: Vec<WorkerDef>,
    /// Per-instance configuration (libp2p identity, data dir, ...).
    /// In normal use this lives in a gitignored `Kunekt.local.toml`
    /// overlay — different operators get different `[node]`s while
    /// sharing the rest of the manifest.
    #[serde(default)]
    node: NodeMeta,
}

#[derive(Deserialize, Default)]
struct NodeMeta {
    /// libp2p keypair material (path to file, or `"auto"` to
    /// derive on first run). Reserved.
    #[serde(default)]
    #[allow(dead_code)]
    identity: Option<String>,
    /// libp2p listen multiaddrs. Reserved.
    #[serde(default)]
    #[allow(dead_code)]
    listen: Vec<String>,
    /// Per-actor redb files live under `{data_dir}/agents/...` and
    /// `{data_dir}/workers/...`. CLI `--data-dir` takes precedence.
    #[serde(default)]
    data_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
struct AgentDef {
    name: String,
    /// Local path to an ELF or pre-compiled .pvm. Mutually exclusive
    /// with `service`.
    #[serde(default)]
    path: Option<PathBuf>,
    /// Registry lookup, e.g. `"kunekt/scheduler@1.2"`. Production
    /// path. Currently errors out — registry resolution lands with
    /// the networking layer.
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    consistency: ConsistencyDef,
    /// Roles this agent provides (e.g. `["registry"]`). Other actors
    /// can address by role via `init` values prefixed `@role-name`.
    /// Operators see this in `vosx list`.
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
    /// Replication group identifier. Only meaningful when
    /// `consistency = "crdt"`. Three forms:
    ///   - omitted / "auto" — derive from `blake2b(name || 0 || blob)`,
    ///     so two replicas of the same code+name auto-share a group
    ///   - 64-char hex string — explicit, for cross-cluster pinning
    ///   - "off" — no replication (DAG stays purely local)
    #[serde(default)]
    replication_id: Option<String>,
    /// Messages to send to this agent immediately after startup.
    /// Each entry is encoded as a TAG_DYNAMIC + rkyv(Msg) payload
    /// and queued via `AgentConfig::init_payloads`. Useful for
    /// kicking a CRDT actor with a per-process unique tag from
    /// the local overlay so two replicas of the same manifest
    /// produce different EffectLogs.
    #[serde(default)]
    on_start: Vec<OnStartMsg>,
    /// Child actors hosted by this agent. Each becomes its own
    /// registered service; the agent typically references them by
    /// name in its own `init` (e.g. `init = { children = [...] }`).
    #[serde(default)]
    actors: Vec<ActorDef>,
}

#[derive(Deserialize)]
struct ActorDef {
    name: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
    /// Same shape as [`AgentDef::replication_id`].
    #[serde(default)]
    replication_id: Option<String>,
    /// Same shape as [`AgentDef::on_start`].
    #[serde(default)]
    on_start: Vec<OnStartMsg>,
}

#[derive(Deserialize, Clone)]
struct OnStartMsg {
    /// Handler name (the actor's `#[msg]` method).
    msg: String,
    /// Arguments to pack into the dynamic `Msg`. Keys must match
    /// the handler's parameter names.
    #[serde(default)]
    args: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ConsistencyDef {
    #[default]
    Ephemeral,
    Local,
    Crdt,
}

impl From<ConsistencyDef> for vos::node::Consistency {
    fn from(c: ConsistencyDef) -> Self {
        match c {
            ConsistencyDef::Ephemeral => vos::node::Consistency::Ephemeral,
            ConsistencyDef::Local => vos::node::Consistency::Local,
            ConsistencyDef::Crdt => vos::node::Consistency::Crdt,
        }
    }
}

#[derive(Deserialize)]
struct WorkerDef {
    name: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    service: Option<String>,
    /// Roles this worker provides (e.g. `["rates"]`).
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

#[cfg(feature = "network")]
fn start_network_if_needed(
    manifest: &Manifest,
    data_dir: Option<&Path>,
    listen_cli: &[String],
    connect_cli: &[String],
) -> Option<vos::network::Network> {
    use std::str::FromStr;

    let parse = |s: &str, kind: &str| -> Option<libp2p::Multiaddr> {
        match libp2p::Multiaddr::from_str(s) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("vosx: ignoring invalid {kind} multiaddr '{s}': {e}");
                None
            }
        }
    };

    let mut listen: Vec<libp2p::Multiaddr> = listen_cli
        .iter()
        .filter_map(|s| parse(s, "listen"))
        .collect();
    listen.extend(
        manifest.node.listen.iter().filter_map(|s| parse(s, "listen")),
    );
    let connect: Vec<libp2p::Multiaddr> = connect_cli
        .iter()
        .filter_map(|s| parse(s, "connect"))
        .collect();

    if listen.is_empty() && connect.is_empty() {
        return None;
    }

    let keypair = match vos::network::load_or_generate_identity(
        manifest.node.identity.as_deref(),
        data_dir,
    ) {
        Ok(kp) => kp,
        Err(e) => die(&format!("identity: {e}")),
    };
    let peer_id = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer_id);
    eprintln!(
        "vosx: node identity {peer_id} (prefix {:#06x})",
        local_prefix,
    );

    Some(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap: connect,
    }))
}

/// Resolve the local file path for an entry that may use `path` (dev)
/// or `service` (registry lookup). Today only `path` is supported;
/// `service` errors out with a clear pointer to networking work.
fn resolve_entry_path(
    name: &str,
    path: &Option<PathBuf>,
    service: &Option<String>,
    dir: &Path,
) -> PathBuf {
    match (path, service) {
        (Some(_), Some(_)) => die(&format!(
            "'{name}': 'service' and 'path' are mutually exclusive — pick one",
        )),
        (None, None) => die(&format!(
            "'{name}': either 'service' or 'path' is required",
        )),
        (None, Some(s)) => die(&format!(
            "'{name}': 'service = {s:?}' requires registry resolution which lands \
             with the networking layer; use 'path' for now",
        )),
        (Some(p), None) => dir.join(p),
    }
}

fn manifest_from(path: Option<PathBuf>) -> (Manifest, PathBuf) {
    let path = path.unwrap_or_else(|| "space.toml".into());
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())));
    let mut manifest: Manifest = toml::from_str(&content)
        .unwrap_or_else(|e| die(&format!("parsing {}: {e}", path.display())));

    // Optional `<basename>.local.toml` overlay. Designed to live
    // gitignored next to the shared manifest: different operators
    // can set `[node]` (libp2p identity, listen addrs, data_dir)
    // independently while the rest of the space stays shared.
    let overlay_path = local_overlay_path(&path);
    if overlay_path.exists() {
        let overlay_content = std::fs::read_to_string(&overlay_path)
            .unwrap_or_else(|e| die(&format!("reading {}: {e}", overlay_path.display())));
        let overlay: LocalOverlay = toml::from_str(&overlay_content)
            .unwrap_or_else(|e| die(&format!("parsing {}: {e}", overlay_path.display())));
        if let Some(node) = overlay.node {
            manifest.node = node;
        }
        // Per-agent `on_start` overrides — by name. Useful for
        // making two replicas of the same manifest fire distinct
        // EffectLogs (e.g. `inc(tag = 1)` on host A,
        // `inc(tag = 2)` on host B) without forking the manifest.
        for ov in overlay.agent {
            let mut applied = false;
            for a in manifest.agent.iter_mut() {
                if a.name == ov.name {
                    a.on_start = ov.on_start;
                    applied = true;
                    break;
                }
                for child in a.actors.iter_mut() {
                    if child.name == ov.name {
                        child.on_start = ov.on_start.clone();
                        applied = true;
                        break;
                    }
                }
                if applied { break; }
            }
            if !applied {
                eprintln!(
                    "vosx: overlay agent '{}' not found in base manifest; ignoring",
                    ov.name,
                );
            }
        }
        eprintln!("vosx: merged overlay from {}", overlay_path.display());
    }

    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    (manifest, dir)
}

/// Derive the local-overlay file path: insert `.local` before the
/// extension. `space.toml` → `space.local.toml`. Anything that
/// doesn't have a `.toml` extension (shouldn't happen in practice)
/// falls back to appending `.local.toml`.
fn local_overlay_path(manifest: &Path) -> PathBuf {
    let stem = manifest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("space");
    let dir = manifest.parent().unwrap_or(Path::new("."));
    dir.join(format!("{stem}.local.toml"))
}

/// Subset of the manifest schema that's allowed in the overlay
/// file. `[node]` for libp2p identity / listen / data_dir, and
/// `[[agent]]` entries for per-host on_start overrides keyed by
/// agent name (the rest of the agent definition can't be
/// overridden — only on_start, since that's the typical use
/// case for "two operators run the same manifest with different
/// kick-off messages").
#[derive(Deserialize, Default)]
struct LocalOverlay {
    #[serde(default)]
    node: Option<NodeMeta>,
    #[serde(default)]
    agent: Vec<LocalOverlayAgent>,
}

#[derive(Deserialize)]
struct LocalOverlayAgent {
    name: String,
    #[serde(default)]
    on_start: Vec<OnStartMsg>,
}

fn is_manifest(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "toml")
}


// ── Helpers ──────────────────────────────────────────────────────────

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .try_init();
}

fn load_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())))
}

fn load_blob(path: &Path) -> Vec<u8> {
    let data = load_file(path);
    match path.extension().and_then(|e| e.to_str()) {
        Some("pvm") => data,
        _ => grey_transpiler::link_elf(&data)
            .unwrap_or_else(|e| die(&format!("transpiling '{}': {e:?}", path.display()))),
    }
}

fn read_stdin() -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| die(&format!("stdin: {e}")));
    buf
}

/// Parse a CLI value string into a `Value`. Auto-types: integers → U64,
/// `true`/`false` → Bool, anything else → Str.
fn parse_cli_value(s: &str) -> vos::value::Value {
    use vos::value::Value;
    if let Ok(b) = s.parse::<bool>() { return Value::Bool(b); }
    if let Ok(n) = s.parse::<i64>() {
        return if n >= 0 { Value::U64(n as u64) } else { Value::I64(n) };
    }
    Value::Str(s.into())
}

/// Resolve a string reference to a `ServiceId` u32. Two forms:
///   `name`     → look up in `name_ids` (declared actor/worker name)
///   `@role`    → look up in `provides_map` (must be unambiguous)
///
/// Forward references and ambiguous role lookups die with a clear
/// message — we resolve in declaration order so the first usage of
/// a peer must come after its `[[agent]]` / `[[worker]]` block.
fn resolve_string_to_id(
    s: &str,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> u32 {
    if let Some(role) = s.strip_prefix('@') {
        match provides_map.get(role) {
            None => die(&format!(
                "no actor or worker provides role '{role}' (referenced by '@{role}')",
            )),
            Some(ids) if ids.is_empty() => die(&format!(
                "no actor or worker provides role '{role}'",
            )),
            Some(ids) if ids.len() > 1 => die(&format!(
                "role '{role}' is provided by {} entries; cannot resolve '@{role}' unambiguously",
                ids.len(),
            )),
            Some(ids) => ids[0],
        }
    } else {
        name_ids.get(s).copied().unwrap_or_else(|| {
            die(&format!(
                "init value '{s}' is not a declared actor or worker (forward reference? use '@role' for role lookup)",
            ))
        })
    }
}

/// Convert a TOML value to a typed `InitValue`, resolving string
/// references against the running map of declared peers.
///
/// Supported coercions:
/// - integer → `u32`/`u64`/`i32` (unchanged)
/// - bool → `bool`
/// - string → `String`, OR a `u32` ServiceId when the string
///   matches a declared actor/worker name and the expected type is
///   `u32`. Strings prefixed with `@` resolve via the `provides`
///   role map.
/// - array → `Vec<u32>`, accepting integers, name-strings, or
///   `@role`-prefixed role lookups.
fn toml_to_init_value(
    val: &toml::Value,
    expected_ty: &str,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> InitValue {
    let ty = expected_ty.replace(' ', "");
    match (val, ty.as_str()) {
        (toml::Value::Integer(n), "u32") => InitValue::U32(*n as u32),
        (toml::Value::Integer(n), "u64") => InitValue::U64(*n as u64),
        (toml::Value::Integer(n), "i32") => InitValue::I32(*n as i32),
        (toml::Value::Boolean(b), "bool") => InitValue::Bool(*b),
        (toml::Value::String(s), "String") => InitValue::Str(s.clone()),
        (toml::Value::String(s), "u32") => {
            InitValue::U32(resolve_string_to_id(s, name_ids, provides_map))
        }
        (toml::Value::Array(arr), "Vec<u32>") => InitValue::ListU32(
            arr.iter()
                .map(|v| match v {
                    toml::Value::Integer(n) => *n as u32,
                    toml::Value::String(s) => resolve_string_to_id(s, name_ids, provides_map),
                    other => die(&format!(
                        "Vec<u32> array element must be integer or actor/worker name, got {other:?}",
                    )),
                })
                .collect(),
        ),
        _ => die(&format!("cannot convert TOML value to {expected_ty}")),
    }
}

/// Convert a TOML value into a `vos::value::Value` for worker init
/// args (which are untyped — we infer from the TOML shape, with
/// strings resolving to ServiceIds when they match a declared name
/// or `@role` reference).
fn toml_to_value(
    val: &toml::Value,
    name_ids: &BTreeMap<String, u32>,
    provides_map: &BTreeMap<String, Vec<u32>>,
) -> vos::value::Value {
    use vos::value::Value;
    match val {
        toml::Value::Integer(n) => {
            if *n >= 0 {
                Value::U64(*n as u64)
            } else {
                Value::I64(*n)
            }
        }
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::String(s) => {
            if let Some(role) = s.strip_prefix('@') {
                Value::U32(resolve_string_to_id(&format!("@{role}"), name_ids, provides_map))
            } else if let Some(&id) = name_ids.get(s) {
                Value::U32(id)
            } else {
                Value::Str(s.clone())
            }
        }
        other => die(&format!("worker init value of unsupported TOML kind: {other:?}")),
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    (hex.len() % 2 == 0).then(||
        (0..hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect::<Option<Vec<_>>>()
    ).flatten()
}

fn exit_with_status(panics: u32) {
    if panics > 0 {
        eprintln!("\nvosx: {panics} panic(s)");
        std::process::exit(1);
    }
    eprintln!("\nvosx: done");
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn print_actor_meta(name: &str, path: &Path, role: &str) {
    let Ok(data) = std::fs::read(path) else {
        println!("  {name} ({role}) — not built");
        return;
    };
    let Some(meta) = vos::metadata::from_elf(&data) else {
        println!("  {name} ({role}) — no metadata");
        return;
    };
    println!("  {} ({role}: {})", name, meta.actor_name);
    if !meta.constructor.is_empty() {
        let params: Vec<_> = meta.constructor.iter()
            .map(|f| format!("{}: {}", f.name, f.ty.replace(' ', "")))
            .collect();
        println!("    new({})", params.join(", "));
    }
    for msg in &meta.messages {
        let kind = if msg.is_query { "query" } else { "cmd" };
        let params: Vec<_> = msg.fields.iter()
            .map(|f| format!("{}: {}", f.name, f.ty.replace(' ', "")))
            .collect();
        if params.is_empty() {
            println!("    {kind} {}()", msg.name);
        } else {
            println!("    {kind} {}({})", msg.name, params.join(", "));
        }
    }
}
