//! `vosx` — run a manifest of VOS actors cooperatively.
//!
//! Usage:
//!     vosx [path/to/Kunekt.toml]             Run all actors
//!     vosx --list [path/to/Kunekt.toml]      List actors and their messages
//!
//! vosx is functionally a single-node JAR chain: same hostcall semantics,
//! same service lifecycle. Actor code is identical for offline (vosx) and
//! online (JAR chain).

use vos::runtime::VosRuntime;
use vos::metadata;
use serde::Deserialize;
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
}

#[derive(Deserialize)]
struct ActorDef {
    name: String,
    path: Option<PathBuf>,
    #[serde(default = "default_format")]
    format: String,
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
    eprintln!("  transpiling '{name}' via link_elf_service");
    match grey_transpiler::link_elf_service(data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: transpiling '{name}': {e:?}");
            process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
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
        cmd_run(&manifest, manifest_dir);
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
            for msg in &meta.messages {
                let kind = if msg.is_query { "query" } else { "cmd" };
                if msg.fields.is_empty() {
                    println!("    {kind} {}()", msg.name);
                } else {
                    let params: Vec<String> = msg.fields.iter()
                        .map(|f| format!("{}: {}", f.name, f.ty))
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

/// Run the full cooperative loop.
fn cmd_run(manifest: &Manifest, manifest_dir: &Path) {
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
        "pvm" => agent_data,
        _ => transpile_elf(&agent_data, &manifest.service.name),
    };
    let agent_blob_idx = runtime.register_service_blob(agent_blob);
    let agent_id = runtime.register_service_from_service_blob(agent_blob_idx);
    eprintln!("  registered '{}' as service {agent_id:?}", manifest.service.name);

    // Step 2: Register actor blobs (dual-entry: refine at PC=0, accumulate at PC=5)
    // Actors use link_elf_service so PC=0 has a jump to _start (needed for invoke).
    let mut actor_ids = Vec::new();
    for actor_def in &manifest.actors {
        let path = resolve_path(manifest_dir, &actor_def.path, &actor_def.name);
        let data = load_file(&path, &actor_def.name);
        eprintln!("  loading '{}' from {}", actor_def.name, path.display());
        let blob = match actor_def.format.as_str() {
            "pvm" => data,
            _ => transpile_elf(&data, &actor_def.name),
        };
        let blob_idx = runtime.register_service_blob(blob);
        let id = runtime.register_service_from_service_blob(blob_idx);
        eprintln!("  registered '{}' as service {id:?}", actor_def.name);
        actor_ids.push(id);
    }

    // Step 3: Write actor IDs to the agent's storage for bootstrap discovery.
    // The agent reads key "__actors" on init: [id_1:u32 LE][id_2:u32 LE]...
    {
        let mut actors_data = Vec::with_capacity(actor_ids.len() * 4);
        for &id in &actor_ids {
            actors_data.extend_from_slice(&id.0.to_le_bytes());
        }
        runtime.storage.write(agent_id, b"__actors", &actors_data);
    }

    // Send an empty transfer to kick-start the agent (triggers first FETCH).
    runtime.send_to(agent_id, Vec::new());

    eprintln!("vosx: running...\n");

    runtime.run();

    eprintln!("\nvosx: done");
}
