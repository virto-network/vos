//! `vosx` — JAM-aligned PVM executor.
//!
//! Run any PVM program, a TOML manifest, or multiple agents concurrently.

use clap::{Parser, Subcommand};
use vos::runtime::VosRuntime;
use vos::metadata;
use vos::init::{InitArgs, InitValue};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to Kunekt.toml manifest (default mode)
    #[arg(global = true)]
    manifest: Option<PathBuf>,

    /// List actors and their messages without running
    #[arg(long)]
    list: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run any PVM/ELF program (dumb JAM host)
    Run(RunArgs),
    /// Run multiple agents concurrently on separate threads
    Node(NodeArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Path to PVM or ELF program
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

    /// Send a "start" message to kick-start a long-running service
    #[arg(short, long)]
    start: bool,
}

#[derive(clap::Args)]
struct NodeArgs {
    /// PVM/ELF programs to run as agents
    programs: Vec<PathBuf>,

    /// Send a "start" message to each agent
    #[arg(short, long)]
    start: bool,
}

// ── Manifest (Kunekt.toml) ───────────────────────────────────────────

#[derive(Deserialize)]
struct Manifest {
    manifest: ManifestMeta,
    service: ServiceDef,
    #[serde(default)]
    actors: Vec<ActorDef>,
}

#[derive(Deserialize)]
struct ManifestMeta {
    name: String,
}

#[derive(Deserialize)]
struct ServiceDef {
    name: String,
    path: Option<PathBuf>,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct ActorDef {
    name: String,
    path: Option<PathBuf>,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default)]
    init: BTreeMap<String, toml::Value>,
}

fn default_format() -> String { "elf".to_string() }

// ── Helpers ──────────────────────────────────────────────────────────

fn load_manifest(path: &Path) -> Manifest {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: reading {}: {e}", path.display());
            process::exit(1);
        }
    };
    match toml::from_str(&content) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: parsing {}: {e}", path.display());
            process::exit(1);
        }
    }
}

fn resolve_path(manifest_dir: &Path, path: &Option<PathBuf>, name: &str) -> PathBuf {
    match path {
        Some(p) => manifest_dir.join(p),
        None => {
            eprintln!("error: '{}' has no path (registry not yet supported)", name);
            process::exit(1);
        }
    }
}

fn load_file(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: reading {}: {e}", path.display());
            process::exit(1);
        }
    }
}

fn load_blob(path: &Path) -> Vec<u8> {
    let data = load_file(path);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "pvm" => data,
        _ => {
            let name = path.display().to_string();
            eprintln!("  transpiling '{name}' via link_elf");
            match grey_transpiler::link_elf(&data) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: transpiling '{name}': {e:?}");
                    process::exit(1);
                }
            }
        }
    }
}

/// Encode a dynamic "start" message as a tagged work item.
fn encode_start_msg() -> Vec<u8> {
    use vos::value::{Msg, TAG_DYNAMIC};
    use vos::Encode;
    let msg = Msg::new("start");
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

fn toml_to_init_value(val: &toml::Value, expected_ty: &str) -> InitValue {
    let ty = expected_ty.replace(' ', "");
    match (val, ty.as_str()) {
        (toml::Value::Integer(n), "u32") => InitValue::U32(*n as u32),
        (toml::Value::Integer(n), "u64") => InitValue::U64(*n as u64),
        (toml::Value::Integer(n), "i32") => InitValue::I32(*n as i32),
        (toml::Value::Boolean(b), "bool") => InitValue::Bool(*b),
        (toml::Value::String(s), "String") => InitValue::Str(s.clone()),
        (toml::Value::Array(arr), "Vec<u32>") => {
            let items: Vec<u32> = arr.iter()
                .map(|v| v.as_integer().expect("expected integer in array") as u32)
                .collect();
            InitValue::ListU32(items)
        }
        _ => {
            eprintln!("error: cannot convert TOML value to {expected_ty}");
            process::exit(1);
        }
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    if hex.len() % 2 != 0 { return None; }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ── Main ─────────────────────────────────────────────────────────────

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Run(args)) => cmd_run(args),
        Some(Command::Node(args)) => cmd_node(args),
        None => {
            let manifest_path = cli.manifest.unwrap_or_else(|| PathBuf::from("Kunekt.toml"));
            let manifest = load_manifest(&manifest_path);
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));

            if cli.list {
                cmd_list(&manifest, manifest_dir);
            } else {
                cmd_manifest(&manifest, manifest_dir);
            }
        }
    }
}

// ── `vosx run` ───────────────────────────────────────────────────────

fn cmd_run(args: RunArgs) {
    let blob = load_blob(&args.program);

    let mut runtime = VosRuntime::with_gas_config(vos::runtime::GasConfig {
        refine_gas: args.gas,
        accumulate_gas_max: args.gas,
        accumulate_gas_default: args.gas,
    });

    let blob_idx = runtime.register_service_blob(blob);
    let id = runtime.register_service(blob_idx);

    eprintln!("vosx run: loaded '{}' as service {id:?}", args.program.display());

    // Collect payloads from --payload and --hex flags
    let mut payloads: Vec<Vec<u8>> = Vec::new();

    for path in &args.payload {
        let data = if path.as_os_str() == "-" {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
                eprintln!("error: reading stdin: {e}");
                process::exit(1);
            });
            buf
        } else {
            load_file(path)
        };
        payloads.push(data);
    }

    for hex_str in &args.hex {
        let data = hex_decode(hex_str).unwrap_or_else(|| {
            eprintln!("error: invalid hex string '{hex_str}'");
            process::exit(1);
        });
        payloads.push(data);
    }

    if args.start {
        payloads.insert(0, encode_start_msg());
    }

    if payloads.is_empty() {
        runtime.send_to(id, Vec::new());
    } else {
        for payload in payloads {
            runtime.send_to(id, payload);
        }
    }

    eprintln!("vosx run: executing...\n");
    runtime.run_blocking();

    if runtime.panics > 0 {
        eprintln!("\nvosx run: program panicked ({} panic(s))", runtime.panics);
        process::exit(1);
    }
    eprintln!("\nvosx run: done");
}

// ── `vosx node` ──────────────────────────────────────────────────────

fn cmd_node(args: NodeArgs) {
    use vos::node::{VosNode, AgentConfig};

    if args.programs.is_empty() {
        eprintln!("error: `vosx node` requires at least one program path");
        process::exit(1);
    }

    let mut node = VosNode::new();

    for path in &args.programs {
        let blob = load_blob(path);
        let init_payloads = if args.start {
            vec![encode_start_msg()]
        } else {
            vec![]
        };

        let id = node.register(AgentConfig {
            blob,
            init_payloads,
            storage: vec![],
        });
        eprintln!("vosx node: registered '{}' as agent {id:?}", path.display());
    }

    eprintln!("vosx node: running {} agent(s)...\n", args.programs.len());
    node.run();

    let results = node.collect();
    let total_panics: u32 = results.iter().map(|r| r.panics).sum();
    for r in &results {
        if r.panics > 0 {
            eprintln!("vosx node: agent {:?} had {} panic(s)", r.id, r.panics);
        }
    }

    eprintln!("\nvosx node: done");
    if total_panics > 0 {
        process::exit(1);
    }
}

// ── `vosx [manifest]` ────────────────────────────────────────────────

fn cmd_list(manifest: &Manifest, manifest_dir: &Path) {
    println!("{}", manifest.manifest.name);
    println!();

    let svc_path = resolve_path(manifest_dir, &manifest.service.path, &manifest.service.name);
    print_actor_meta(&manifest.service.name, &svc_path, "service");

    for actor_def in &manifest.actors {
        let path = resolve_path(manifest_dir, &actor_def.path, &actor_def.name);
        print_actor_meta(&actor_def.name, &path, "actor");
    }
}

fn print_actor_meta(name: &str, path: &Path, role: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            println!("  {name} ({role}) — not built");
            return;
        }
    };

    match metadata::from_elf(&data) {
        Some(meta) => {
            println!("  {} ({role}: {})", name, meta.actor_name);
            if !meta.constructor.is_empty() {
                let params: Vec<String> = meta.constructor.iter()
                    .map(|f| {
                        let ty = f.ty.replace(' ', "");
                        format!("{}: {ty}", f.name)
                    })
                    .collect();
                println!("    new({})", params.join(", "));
            }
            for msg in &meta.messages {
                let kind = if msg.is_query { "query" } else { "cmd" };
                if msg.fields.is_empty() {
                    println!("    {kind} {}()", msg.name);
                } else {
                    let params: Vec<String> = msg.fields.iter()
                        .map(|f| {
                            let ty = f.ty.replace(' ', "");
                            format!("{}: {ty}", f.name)
                        })
                        .collect();
                    println!("    {kind} {}({})", msg.name, params.join(", "));
                }
            }
        }
        None => {
            println!("  {name} ({role}) — no metadata");
        }
    }
}

fn cmd_manifest(manifest: &Manifest, manifest_dir: &Path) {
    eprintln!(
        "vosx: manifest '{}' — 1 service + {} actor(s)",
        manifest.manifest.name,
        manifest.actors.len()
    );

    let mut runtime = VosRuntime::new();

    // Step 1: Register the agent service
    let svc_path = resolve_path(manifest_dir, &manifest.service.path, &manifest.service.name);
    let agent_data = load_file(&svc_path);
    eprintln!("  loading '{}' from {}", manifest.service.name, svc_path.display());
    let agent_blob = match manifest.service.format.as_str() {
        "pvm" => agent_data.clone(),
        _ => load_blob(&svc_path),
    };
    let agent_blob_idx = runtime.register_service_blob(agent_blob);
    let agent_id = runtime.register_service(agent_blob_idx);
    eprintln!("  registered '{}' as service {agent_id:?}", manifest.service.name);

    // Step 2: Register actor blobs
    let mut actor_ids = Vec::new();
    for actor_def in &manifest.actors {
        let path = resolve_path(manifest_dir, &actor_def.path, &actor_def.name);
        let data = load_file(&path);
        eprintln!("  loading '{}' from {}", actor_def.name, path.display());
        let blob = match actor_def.format.as_str() {
            "pvm" => data.clone(),
            _ => load_blob(&path),
        };
        let blob_idx = runtime.register_service_blob(blob);
        let id = runtime.register_service(blob_idx);
        eprintln!("  registered '{}' as service {id:?}", actor_def.name);
        actor_ids.push(id);

        if !actor_def.init.is_empty() {
            let meta = metadata::from_elf(&data);
            let mut args = InitArgs::new();
            for (key, val) in &actor_def.init {
                let ty = meta.as_ref()
                    .and_then(|m| m.constructor.iter().find(|f| f.name == *key))
                    .map(|f| f.ty.as_str())
                    .unwrap_or("String");
                args = args.with(key.as_str(), toml_to_init_value(val, ty));
            }
            let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
            runtime.storage.write(id, vos::lifecycle::INIT_KEY, &encoded);
        }
    }

    // Step 3: Build init args for the service
    {
        let mut args = InitArgs::new();
        let children: Vec<u32> = actor_ids.iter().map(|id| id.0).collect();
        args = args.with("children", InitValue::ListU32(children));

        if let Some(meta) = metadata::from_elf(&agent_data) {
            for field in &meta.constructor {
                if field.name == "children" { continue; }
                if let Some(val) = manifest.service.init.get(&field.name) {
                    args = args.with(&field.name, toml_to_init_value(val, &field.ty));
                }
            }
        }

        let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
        runtime.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);
    }

    // Send "start" to kick-start the agent
    runtime.send_to(agent_id, encode_start_msg());

    eprintln!("vosx: running...\n");
    runtime.run_blocking();
    eprintln!("\nvosx: done");
}
