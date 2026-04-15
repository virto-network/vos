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
        /// Load native worker plugins (.so files)
        #[arg(long, value_name = "FILE")]
        worker: Vec<PathBuf>,
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
        Some(Command::Node { programs, registry, worker }) => {
            cmd_node(&programs, registry.as_deref(), &worker);
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
            cmd_manifest(&m, &dir);
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

fn cmd_node(programs: &[PathBuf], registry: Option<&Path>, workers: &[PathBuf]) {
    use vos::node::{AgentConfig, WorkerConfig, VosNode};

    let mut node = VosNode::new();

    // Load registry at ServiceId(0) if specified
    if let Some(reg_path) = registry {
        let blob = load_blob(reg_path);
        let id = node.register(AgentConfig {
            blob,
            init_payloads: vec![],
            storage: vec![],
        });
        eprintln!("vosx: registry '{}' as {id}", reg_path.display());
    }

    for path in programs {
        let id = node.register(AgentConfig {
            blob: load_blob(path),
            init_payloads: vec![],
            storage: vec![],
        });
        eprintln!("vosx: registered '{}' as {id:?}", path.display());
    }

    for path in workers {
        let id = node.register_worker(WorkerConfig {
            path: path.clone(),
        });
        eprintln!("vosx: worker '{}' as {id:?}", path.display());
    }

    let total = programs.len() + workers.len();
    eprintln!("vosx: running {total} service(s) ({} PVM + {} worker)...\n",
        programs.len(), workers.len());
    node.run();

    let panics: u32 = node.collect().iter().map(|r| r.panics).sum();
    exit_with_status(panics);
}

fn cmd_list(manifest: &Manifest, dir: &Path) {
    println!("{}\n", manifest.manifest.name);
    print_actor_meta(&manifest.service.name,
        &resolve_path(dir, &manifest.service.path, &manifest.service.name), "service");
    for a in &manifest.actors {
        print_actor_meta(&a.name, &resolve_path(dir, &a.path, &a.name), "actor");
    }
}

fn cmd_manifest(manifest: &Manifest, dir: &Path) {
    eprintln!("vosx: '{}' — 1 service + {} actor(s)",
        manifest.manifest.name, manifest.actors.len());

    let mut rt = VosRuntime::new();

    let agent_data = load_file(&resolve_path(dir, &manifest.service.path, &manifest.service.name));
    let agent_blob = load_blob(&resolve_path(dir, &manifest.service.path, &manifest.service.name));
    let idx = rt.register_service_blob(agent_blob);
    let agent_id = rt.register_service(idx);

    let actor_ids: Vec<_> = manifest.actors.iter().map(|a| {
        let path = resolve_path(dir, &a.path, &a.name);
        let data = load_file(&path);
        let blob = load_blob(&path);
        let idx = rt.register_service_blob(blob);
        let id = rt.register_service(idx);
        write_init_args(&mut rt, id, &a.init, &data);
        id
    }).collect();

    // Agent init: inject children + manifest overrides
    let mut args = InitArgs::new()
        .with("children", InitValue::ListU32(actor_ids.iter().map(|id| id.0).collect()));
    if let Some(meta) = vos::metadata::from_elf(&agent_data) {
        for f in meta.constructor.iter().filter(|f| f.name != "children") {
            if let Some(val) = manifest.service.init.get(&f.name) {
                args = args.with(&f.name, toml_to_init_value(val, &f.ty));
            }
        }
    }
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);

    // Trigger first tick — the actor's on_start hook runs automatically on cold start.
    rt.send_to(agent_id, Vec::new());
    eprintln!("vosx: running...\n");
    rt.run_blocking();
    eprintln!("\nvosx: done");
}

// ── Manifest ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Manifest {
    manifest: ManifestMeta,
    service: ServiceDef,
    #[serde(default)]
    actors: Vec<ActorDef>,
}

#[derive(Deserialize)]
struct ManifestMeta { name: String }

#[derive(Deserialize)]
struct ServiceDef {
    name: String,
    path: Option<PathBuf>,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct ActorDef {
    name: String,
    path: Option<PathBuf>,
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

fn write_init_args(rt: &mut VosRuntime, id: vos::abi::service::ServiceId,
    init: &BTreeMap<String, toml::Value>, elf_data: &[u8])
{
    if init.is_empty() { return; }
    let meta = vos::metadata::from_elf(elf_data);
    let mut args = InitArgs::new();
    for (key, val) in init {
        let ty = meta.as_ref()
            .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
            .map(|f| f.ty.as_str())
            .unwrap_or("String");
        args = args.with(key, toml_to_init_value(val, ty));
    }
    let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
    rt.storage.write(id, vos::lifecycle::INIT_KEY, &encoded);
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

fn resolve_path(dir: &Path, path: &Option<PathBuf>, name: &str) -> PathBuf {
    path.as_ref().map(|p| dir.join(p))
        .unwrap_or_else(|| die(&format!("'{name}' has no path")))
}

fn toml_to_init_value(val: &toml::Value, expected_ty: &str) -> InitValue {
    let ty = expected_ty.replace(' ', "");
    match (val, ty.as_str()) {
        (toml::Value::Integer(n), "u32") => InitValue::U32(*n as u32),
        (toml::Value::Integer(n), "u64") => InitValue::U64(*n as u64),
        (toml::Value::Integer(n), "i32") => InitValue::I32(*n as i32),
        (toml::Value::Boolean(b), "bool") => InitValue::Bool(*b),
        (toml::Value::String(s), "String") => InitValue::Str(s.clone()),
        (toml::Value::Array(arr), "Vec<u32>") => InitValue::ListU32(
            arr.iter().map(|v| v.as_integer().expect("integer") as u32).collect()),
        _ => die(&format!("cannot convert TOML value to {expected_ty}")),
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
