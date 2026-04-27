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
    /// for `Kunekt.toml` in the current directory.
    Start {
        manifest: Option<PathBuf>,
        /// Override the data directory (default: `data`). Per-actor
        /// persistence is gated by each actor's `consistency` field.
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence entirely (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
    },
    /// List actors in a manifest
    List {
        manifest: Option<PathBuf>,
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


        Some(Command::Start { manifest, data_dir, no_persist }) => {
            let (m, dir) = manifest_from(manifest);
            let pers_dir = if no_persist { None } else { data_dir.as_deref() };
            cmd_start(&m, &dir, pers_dir);
        }
        Some(Command::List { manifest }) => {
            let (m, dir) = manifest_from(manifest);
            cmd_list(&m, &dir);
        }
        None if cli.file.as_ref().is_some_and(|p| !is_manifest(p)) => {
            cmd_run(cli.file.as_ref().unwrap(), &[], &[], 100_000_000);
        }
        None => {
            let (m, dir) = manifest_from(cli.file);
            cmd_start(&m, &dir, Some(Path::new("data")));
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
    let space = &manifest.space;
    println!("space: {}", space.name);
    if let Some(hs) = &space.hyperspace {
        println!("  hyperspace: {hs}");
    }
    println!();
    for a in &manifest.actor {
        let role = match (&a.well_known, a.consistency) {
            (Some(wk), c) => format!("actor [{wk}] {c:?}"),
            (None, c) => format!("actor {c:?}"),
        };
        print_actor_meta(&a.name, &dir.join(&a.path), &role);
    }
    for w in &manifest.worker {
        let path = dir.join(&w.path);
        if path.exists() {
            println!("  {} (worker) — {}", w.name, path.display());
        } else {
            println!("  {} (worker) — not built ({})", w.name, path.display());
        }
    }
}

/// Run the space defined by `manifest`.
///
/// Workers register first (they're the I/O boundary, and PVM agents
/// often hold worker IDs in their init args); then actors register
/// in declaration order. The `name_ids` map is built incrementally,
/// so an actor / worker can reference any peer declared earlier in
/// the manifest by name in its init args. Forward references error
/// out at startup with a clear message.
fn cmd_start(manifest: &Manifest, dir: &Path, data_dir: Option<&Path>) {
    use vos::node::{AgentConfig, VosNode, WorkerConfig};
    use vos::value::Args;

    let space = &manifest.space;
    eprintln!(
        "vosx: starting space '{}' ({} actor(s), {} worker(s))",
        space.name,
        manifest.actor.len(),
        manifest.worker.len(),
    );
    if let Some(hs) = &space.hyperspace {
        eprintln!("vosx: hyperspace '{hs}' (declared; networking lands separately)");
    }

    // Sanity: no two declarations share a name.
    {
        let mut seen = BTreeMap::<&str, &str>::new();
        for a in &manifest.actor {
            if seen.insert(a.name.as_str(), "actor").is_some() {
                die(&format!("duplicate name '{}' in manifest", a.name));
            }
        }
        for w in &manifest.worker {
            if seen.insert(w.name.as_str(), "worker").is_some() {
                die(&format!("duplicate name '{}' in manifest", w.name));
            }
        }
    }

    let mut node = VosNode::new();
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();

    // Workers first: their IDs become resolvable for actor init args
    // that reference workers by name (the common case).
    for w in &manifest.worker {
        let path = dir.join(&w.path);
        let mut cfg = if w.init.is_empty() {
            WorkerConfig::new(path)
        } else {
            let mut args = Args::new();
            for (k, v) in &w.init {
                args = args.with(k, toml_to_value(v, &name_ids));
            }
            WorkerConfig::with_args(path, &args)
        };
        if let Some(d) = data_dir {
            cfg = cfg.persist(d);
        }
        let id = node.register_worker(cfg);
        eprintln!("vosx: worker '{}' as {id}", w.name);
        name_ids.insert(w.name.clone(), id.0);
    }

    // Actors next, in declaration order. Init args resolve against
    // workers + already-registered actors.
    for a in &manifest.actor {
        let path = dir.join(&a.path);
        let elf_data = load_file(&path);
        let blob = load_blob(&path);

        let mut cfg = AgentConfig::new(blob).with_consistency(a.consistency.into());
        if let Some(d) = data_dir {
            cfg = cfg.persist(d);
        }

        if !a.init.is_empty() {
            let meta = vos::metadata::from_elf(&elf_data);
            let mut args = InitArgs::new();
            for (key, val) in &a.init {
                let ty = meta
                    .as_ref()
                    .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
                    .map(|f| f.ty.as_str())
                    .unwrap_or("String");
                args = args.with(key, toml_to_init_value(val, ty, &name_ids));
            }
            let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
            cfg = cfg.with_storage(vec![(vos::lifecycle::INIT_KEY.to_vec(), encoded.to_vec())]);
        }

        let id = node.register(cfg);
        let role = a
            .well_known
            .as_deref()
            .map(|r| format!(" [{r}]"))
            .unwrap_or_default();
        eprintln!(
            "vosx: actor '{}' as {id} ({:?}{role})",
            a.name, a.consistency,
        );
        name_ids.insert(a.name.clone(), id.0);
    }

    eprintln!("vosx: running space '{}'...\n", space.name);
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

// ── Manifest ─────────────────────────────────────────────────────────
//
// One vosx instance runs one space. The manifest declares the space's
// identity, the actors and workers it hosts, and (when networking
// lands) its membership in a hyperspace. Spaces with the same manifest
// will be able to join as peers.

#[derive(Deserialize)]
struct Manifest {
    space: SpaceMeta,
    #[serde(default)]
    actor: Vec<ActorDef>,
    #[serde(default)]
    worker: Vec<WorkerDef>,
}

#[derive(Deserialize)]
struct SpaceMeta {
    name: String,
    /// Optional hyperspace this space joins. Reserved for the
    /// networking layer — currently parsed and reported but inert.
    #[serde(default)]
    hyperspace: Option<String>,
    /// Optional libp2p identity material (path to keypair, or
    /// "auto" to derive on first run). Reserved field — read
    /// when the networking layer lands.
    #[serde(default)]
    #[allow(dead_code)]
    identity: Option<String>,
}

#[derive(Deserialize)]
struct ActorDef {
    name: String,
    path: PathBuf,
    #[serde(default)]
    consistency: ConsistencyDef,
    /// Optional named role within the space (e.g. `"registry"`).
    /// Surfaced to operators and reserved for in-space discovery.
    #[serde(default)]
    well_known: Option<String>,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize, Default, Clone, Copy, Debug)]
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
    path: PathBuf,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

fn manifest_from(path: Option<PathBuf>) -> (Manifest, PathBuf) {
    let path = path.unwrap_or_else(|| "Kunekt.toml".into());
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())));
    let manifest: Manifest = toml::from_str(&content)
        .unwrap_or_else(|e| die(&format!("parsing {}: {e}", path.display())));
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    (manifest, dir)
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

/// Convert a TOML value to a typed `InitValue`, resolving string
/// references against the running map of declared peers.
///
/// Supported coercions:
/// - integer → `u32`/`u64`/`i32` (unchanged)
/// - bool → `bool`
/// - string → `String`, OR a `u32` ServiceId when the string
///   matches a declared actor/worker name and the expected type is
///   `u32`
/// - array → `Vec<u32>`, accepting integers or name-strings
fn toml_to_init_value(
    val: &toml::Value,
    expected_ty: &str,
    name_ids: &BTreeMap<String, u32>,
) -> InitValue {
    let ty = expected_ty.replace(' ', "");
    let resolve_name = |s: &str| -> u32 {
        name_ids.get(s).copied().unwrap_or_else(|| {
            die(&format!(
                "init value '{s}' is not a declared actor or worker (forward reference?)",
            ))
        })
    };
    match (val, ty.as_str()) {
        (toml::Value::Integer(n), "u32") => InitValue::U32(*n as u32),
        (toml::Value::Integer(n), "u64") => InitValue::U64(*n as u64),
        (toml::Value::Integer(n), "i32") => InitValue::I32(*n as i32),
        (toml::Value::Boolean(b), "bool") => InitValue::Bool(*b),
        (toml::Value::String(s), "String") => InitValue::Str(s.clone()),
        (toml::Value::String(s), "u32") => InitValue::U32(resolve_name(s)),
        (toml::Value::Array(arr), "Vec<u32>") => InitValue::ListU32(
            arr.iter()
                .map(|v| match v {
                    toml::Value::Integer(n) => *n as u32,
                    toml::Value::String(s) => resolve_name(s),
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
/// strings resolving to ServiceIds when they match a declared name).
fn toml_to_value(val: &toml::Value, name_ids: &BTreeMap<String, u32>) -> vos::value::Value {
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
            if let Some(&id) = name_ids.get(s) {
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
