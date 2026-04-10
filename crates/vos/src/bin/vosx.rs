//! `vosx` — JAM-aligned PVM executor.
//!
//! Usage:
//!     vosx run <program.pvm|program.elf> [--payload file] ...  Run any PVM program
//!     vosx [path/to/Kunekt.toml]                               Run a manifest
//!     vosx --list [path/to/Kunekt.toml]                        List actors
//!
//! `vosx run` is the "dumb host" mode: it loads a single PVM/ELF blob,
//! delivers payload(s) via FETCH, runs refine, and prints the output.
//! No manifest, no framework assumptions — any conformant JAM service works.
//!
//! The manifest mode (`vosx [Kunekt.toml]`) is sugar that translates a
//! TOML manifest into the same transfer-based delivery.

use vos::runtime::VosRuntime;
use vos::metadata;
use vos::init::{InitArgs, InitValue};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process;

// --- Manifest (Kunekt.toml) ---

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

// ---

fn resolve_path(manifest_dir: &Path, path: &Option<PathBuf>, name: &str) -> PathBuf {
    match path {
        Some(p) => manifest_dir.join(p),
        None => {
            eprintln!("error: '{}' has no path (registry not yet supported)", name);
            process::exit(1);
        }
    }
}

fn load_file(path: &Path, _name: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: reading {}: {e}", path.display());
            process::exit(1);
        }
    }
}

fn transpile_elf(data: &[u8], name: &str) -> Vec<u8> {
    eprintln!("  transpiling '{name}' via link_elf");
    match grey_transpiler::link_elf(data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: transpiling '{name}': {e:?}");
            process::exit(1);
        }
    }
}

/// Convert a TOML value to an InitValue using the expected type from metadata.
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

fn print_help() {
    println!("vosx — JAM-aligned PVM executor\n");
    println!("Usage:");
    println!("  vosx run <program.pvm|.elf> [OPTIONS]    Run any PVM program");
    println!("  vosx node <prog1> <prog2> ...            Run multiple agents concurrently");
    println!("  vosx [MANIFEST]                          Run a TOML manifest");
    println!("  vosx --list [MANIFEST]                   List actors\n");
    println!("Run options:");
    println!("  --payload <file>    Deliver file contents as a FETCH work item (repeatable)");
    println!("  --payload -         Read payload from stdin");
    println!("  --hex <hex>         Deliver hex-encoded bytes as a FETCH work item");
    println!("  --gas <amount>      Set gas limit (default: 100_000_000)\n");
    println!("Manifest options:");
    println!("  --list              List actors and their messages without running\n");
    println!("General:");
    println!("  -h, --help          Show this help");
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }

    // Subcommand dispatch
    if args.len() > 1 && args[1] == "run" {
        cmd_run_raw(&args[2..]);
    } else if args.len() > 1 && args[1] == "node" {
        cmd_node(&args[2..]);
    } else {
        let list_mode = args.iter().any(|a| a == "--list");
        let manifest_path = args.iter()
            .filter(|a| !a.starts_with('-') && *a != &args[0])
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("Kunekt.toml"));

        let manifest = load_manifest(&manifest_path);
        let manifest_dir = manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."));

        if list_mode {
            cmd_list(&manifest, manifest_dir);
        } else {
            cmd_run_manifest(&manifest, manifest_dir);
        }
    }
}

/// List all actors and their messages by reading ELF metadata.
fn cmd_list(manifest: &Manifest, manifest_dir: &Path) {
    println!("{}", manifest.manifest.name);
    println!();

    // Service
    let svc_path = resolve_path(manifest_dir, &manifest.service.path, &manifest.service.name);
    print_actor_meta(&manifest.service.name, &svc_path, "service");

    // Actors
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

// ── Raw run mode ─────────────────────────────────────────────────────

/// Run a single PVM/ELF program with optional payloads. This is the
/// "dumb host" mode — no manifest, no framework assumptions.
fn cmd_run_raw(args: &[String]) {
    use std::io::Read;

    if args.is_empty() {
        eprintln!("error: `vosx run` requires a program path");
        eprintln!("Usage: vosx run <program.pvm|.elf> [--payload file] ...");
        process::exit(1);
    }

    let program_path = PathBuf::from(&args[0]);
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut gas: Option<u64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--payload" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --payload requires a file path (or - for stdin)");
                    process::exit(1);
                }
                let data = if args[i] == "-" {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
                        eprintln!("error: reading stdin: {e}");
                        process::exit(1);
                    });
                    buf
                } else {
                    load_file(Path::new(&args[i]), &args[i])
                };
                payloads.push(data);
            }
            "--hex" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --hex requires a hex string");
                    process::exit(1);
                }
                let hex = args[i].trim_start_matches("0x");
                let data = hex_decode(hex).unwrap_or_else(|| {
                    eprintln!("error: invalid hex string");
                    process::exit(1);
                });
                payloads.push(data);
            }
            "--gas" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --gas requires a number");
                    process::exit(1);
                }
                gas = Some(args[i].replace('_', "").parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid gas value");
                    process::exit(1);
                }));
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                process::exit(1);
            }
        }
        i += 1;
    }

    let data = load_file(&program_path, &program_path.display().to_string());
    let ext = program_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let blob = match ext {
        "pvm" => data,
        _ => transpile_elf(&data, &program_path.display().to_string()),
    };

    let mut runtime = VosRuntime::new();
    if let Some(g) = gas {
        runtime = VosRuntime::with_gas_config(vos::runtime::GasConfig {
            refine_gas: g,
            accumulate_gas_max: g,
            accumulate_gas_default: g,
        });
    }

    let blob_idx = runtime.register_service_blob(blob);
    let id = runtime.register_service(blob_idx);

    eprintln!("vosx run: loaded '{}' as service {id:?}", program_path.display());

    // Deliver payloads as transfers (each becomes a FETCH item)
    if payloads.is_empty() {
        // Send an empty transfer to kick-start the service
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

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 { return None; }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ── Multi-agent node mode ────────────────────────────────────────────

/// Run multiple agents concurrently, each on its own thread.
/// Cross-agent transfers are routed through the node's mailbox.
fn cmd_node(args: &[String]) {
    use vos::node::{VosNode, AgentConfig};

    if args.is_empty() {
        eprintln!("error: `vosx node` requires at least one program path");
        eprintln!("Usage: vosx node <prog1.elf> <prog2.elf> ...");
        process::exit(1);
    }

    let mut node = VosNode::new();

    for arg in args {
        if arg.starts_with('-') {
            eprintln!("error: unknown option '{arg}' (node mode takes program paths only)");
            process::exit(1);
        }

        let path = PathBuf::from(arg);
        let data = load_file(&path, arg);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let blob = match ext {
            "pvm" => data,
            _ => transpile_elf(&data, arg),
        };

        let id = node.register(AgentConfig {
            blob,
            init_payloads: vec![],
            storage: vec![],
        });
        eprintln!("vosx node: registered '{}' as agent {id:?}", path.display());
    }

    eprintln!("vosx node: running {} agent(s)...\n", args.len());
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

// ── Manifest run mode ────────────────────────────────────────────────

/// Run the full cooperative loop.
fn cmd_run_manifest(manifest: &Manifest, manifest_dir: &Path) {
    eprintln!(
        "vosx: manifest '{}' — 1 service + {} actor(s)",
        manifest.manifest.name,
        manifest.actors.len()
    );

    let mut runtime = VosRuntime::new();

    // Step 1: Register the agent service (dual-entry blob with refine+accumulate)
    let svc_path = resolve_path(manifest_dir, &manifest.service.path, &manifest.service.name);
    let agent_data = load_file(&svc_path, &manifest.service.name);
    eprintln!("  loading '{}' from {}", manifest.service.name, svc_path.display());
    let agent_blob = match manifest.service.format.as_str() {
        "pvm" => agent_data.clone(),
        _ => transpile_elf(&agent_data, &manifest.service.name),
    };
    let agent_blob_idx = runtime.register_service_blob(agent_blob);
    let agent_id = runtime.register_service(agent_blob_idx);
    eprintln!("  registered '{}' as service {agent_id:?}", manifest.service.name);

    // Step 2: Register actor blobs (dual-entry: refine at PC=0, accumulate at PC=5)
    // Actors use link_elf_service so PC=0 has a jump to _start (needed for invoke).
    let mut actor_ids = Vec::new();
    for actor_def in &manifest.actors {
        let path = resolve_path(manifest_dir, &actor_def.path, &actor_def.name);
        let data = load_file(&path, &actor_def.name);
        eprintln!("  loading '{}' from {}", actor_def.name, path.display());
        let blob = match actor_def.format.as_str() {
            "pvm" => data.clone(),
            _ => transpile_elf(&data, &actor_def.name),
        };
        let blob_idx = runtime.register_service_blob(blob);
        let id = runtime.register_service(blob_idx);
        eprintln!("  registered '{}' as service {id:?}", actor_def.name);
        actor_ids.push(id);

        // Write actor init args from manifest
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

    // Step 3: Build init args for the service.
    // Convention: auto-inject "children" with registered actor IDs.
    {
        let mut args = InitArgs::new();

        // Auto-inject children from [[actors]]
        let children: Vec<u32> = actor_ids.iter().map(|id| id.0).collect();
        args = args.with("children", InitValue::ListU32(children));

        // Merge explicit init values from manifest
        if let Some(meta) = metadata::from_elf(&agent_data) {
            for field in &meta.constructor {
                if field.name == "children" { continue; } // already injected
                if let Some(val) = manifest.service.init.get(&field.name) {
                    args = args.with(&field.name, toml_to_init_value(val, &field.ty));
                }
            }
        }

        let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args).unwrap();
        runtime.storage.write(agent_id, vos::lifecycle::INIT_KEY, &encoded);
    }

    // Send a dynamic "start" message to kick-start the agent. Encoded
    // as a tagged Msg so the framework's dispatch_one decodes it via
    // FromDynamic — the agent's `start` handler then runs.
    {
        use vos::value::{Msg, TAG_DYNAMIC};
        use vos::Encode;
        let msg = Msg::new("start");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        runtime.send_to(agent_id, payload);
    }

    eprintln!("vosx: running...\n");

    runtime.run_blocking();

    eprintln!("\nvosx: done");
}
