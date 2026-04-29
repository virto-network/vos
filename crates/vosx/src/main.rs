//! `vosx` — JAM-aligned PVM executor.

use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vos::runtime::VosRuntime;

mod manifest;
use manifest::{
    apply_init, encode_on_start, is_manifest, manifest_from, resolve_entry_path,
    resolve_replication_id, toml_to_value, ConsistencyDef, Manifest,
};

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
    let network = start_network_if_needed(manifest, data_dir.as_deref(), listen_cli, connect_cli);

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
    let mut node = match &network {
        Some(net) => VosNode::with_prefix(net.local_prefix()),
        None => VosNode::new(),
    };
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
    let networked = network.is_some();
    if let Some(net) = network {
        node.attach_network(net);
    }

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
// name via the registry actor's `resolve` message, fire the
// invoke, and exit.
// No data dir, no long-lived state — the node is gone after the
// command returns.

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
            // Resolve via the macro-generated `RegistryClient`.
            // Returns 0 when the name isn't registered; we surface
            // that as "not found" since the registry's own ID
            // (also 0) is never a useful resolution target.
            let id = registry::RegistryClient::at(node, ServiceId::REGISTRY)
                .resolve(target_str.to_string())
                .unwrap_or_else(|e| die(&format!("resolve '{target_str}': {e}")));
            if id == 0 {
                eprintln!("'{target_str}' not registered");
                std::process::exit(1);
            }
            ServiceId(id)
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

enum ParsedArg { U32(u32), U64(u64), Bool(bool), Str(String) }

/// Parse a `--arg key=value` value. Optional `type:` prefix
/// pins the wire type (`u32:42`, `u64:42`, `bool:true`,
/// `str:42`); without one we autotype: `true`/`false` → bool,
/// integer → u64, anything else → string. Use a prefix when
/// the actor's handler takes a narrower integer type — `u64`
/// will silently no-op against a `u32` handler.

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
/// registry via the macro-generated `RegistryClient`. The local
/// replica fans out via the CRDT layer; on a single-host setup
/// this is just a same-process invoke.
fn flush_registry_announces(node: &vos::node::VosNode, plans: &[AnnouncePlan]) {
    let client = registry::RegistryClient::at(node, vos::abi::service::ServiceId::REGISTRY);
    for plan in plans {
        match client.announce(
            plan.name.clone(),
            plan.owner_prefix as u32,
            plan.service_id as u32,
            plan.roles.clone(),
        ) {
            Ok(()) => eprintln!("vosx: registered '{}' in registry", plan.name),
            Err(e) => eprintln!(
                "vosx: warning: registry announce for '{}' failed: {e}",
                plan.name,
            ),
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

/// Convert a TOML value into a `vos::value::Value` for worker init
/// args (which are untyped — we infer from the TOML shape, with
/// strings resolving to ServiceIds when they match a declared name
/// or `@role` reference).

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

pub(crate) fn die(msg: &str) -> ! {
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
