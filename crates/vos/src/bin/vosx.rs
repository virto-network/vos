//! `vosx` — run a manifest of VOS actors cooperatively.
//!
//! Usage:
//!     vosx [path/to/Kunekt.toml]
//!
//! vosx is functionally a single-node JAR chain: same hostcall semantics,
//! same service lifecycle. Actor code is identical for offline (vosx) and
//! online (JAR chain).

use vos::manifest::Manifest;
use vos::runtime::VosRuntime;
use std::path::PathBuf;
use std::process;

fn main() {
    let manifest_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("Kunekt.toml"));

    eprintln!("vosx: loading {}", manifest_path.display());

    let manifest = match Manifest::load(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "vosx: manifest '{}' — {} service(s)",
        manifest.manifest.name,
        manifest.actors.len()
    );

    let manifest_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut runtime = VosRuntime::new();
    let mut service_ids = Vec::new();

    for svc_def in &manifest.actors {
        let file_path = match &svc_def.path {
            Some(p) => manifest_dir.join(p),
            None => {
                eprintln!(
                    "error: service '{}' has no path (registry not yet supported)",
                    svc_def.name
                );
                process::exit(1);
            }
        };

        let file_data = match std::fs::read(&file_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: reading {}: {e}", file_path.display());
                process::exit(1);
            }
        };

        let (pvm_blob, is_service) = match svc_def.format.as_str() {
            "pvm" => {
                eprintln!("  loading '{}' from {}", svc_def.name, file_path.display());
                (file_data, false)
            }
            "elf" | _ => {
                eprintln!("  transpiling '{}' from {}", svc_def.name, file_path.display());
                // Use link_elf_service for dual-entry (refine at PC=0, accumulate at PC=5).
                // Runtime starts at PC=5 (accumulate) in vosx mode.
                match grey_transpiler::link_elf_service(&file_data) {
                    Ok(b) => (b, true),
                    Err(e) => {
                        eprintln!("error: transpiling '{}': {e:?}", svc_def.name);
                        process::exit(1);
                    }
                }
            }
        };

        let blob_idx = if is_service {
            runtime.register_service_blob(pvm_blob)
        } else {
            runtime.register_blob(pvm_blob)
        };
        let id = if is_service {
            runtime.register_service_from_service_blob(blob_idx)
        } else {
            runtime.register_service(blob_idx)
        };
        eprintln!("  registered '{}' as service {id:?}", svc_def.name);
        service_ids.push((svc_def.name.clone(), id));
    }

    // Send an empty init item to each service to trigger construction
    for (_name, id) in &service_ids {
        runtime.send_to(*id, Vec::new());
    }

    eprintln!("vosx: running...\n");

    runtime.run();

    eprintln!("\nvosx: done");
}
