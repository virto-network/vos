//! `vosx` — run a manifest of VOS actors cooperatively.
//!
//! Usage:
//!     vosx [path/to/Kunekt.toml]
//!
//! vosx is functionally a single-node JAR chain: same hostcall semantics,
//! same service lifecycle. For development and testing.

use vos::manifest::Manifest;
use vos::pvm_driver::{PvmDriver, RawMsg};
use vos::scheduler::{Scheduler, TickResult};
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

    let mut driver = PvmDriver::new();
    let mut blob_indices = Vec::new();

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

        let pvm_blob = match svc_def.format.as_str() {
            "pvm" => {
                eprintln!("  loading '{}' from {}", svc_def.name, file_path.display());
                file_data
            }
            "elf" | _ => {
                eprintln!("  transpiling '{}' from {}", svc_def.name, file_path.display());
                match grey_transpiler::link_elf(&file_data) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("error: transpiling '{}': {e:?}", svc_def.name);
                        process::exit(1);
                    }
                }
            }
        };

        let blob_idx = driver.register_blob(pvm_blob);
        blob_indices.push((svc_def.name.clone(), blob_idx));
    }

    let mut sched: Scheduler<RawMsg, PvmDriver, 64, 16> = Scheduler::new(driver);

    for (name, blob_idx) in &blob_indices {
        match sched.spawn() {
            Some(id) => {
                let status = sched.driver_mut().spawn_blob(id, *blob_idx);
                eprintln!("  spawned '{name}' as service {id:?} — {status:?}");
            }
            None => {
                eprintln!("error: too many services");
                process::exit(1);
            }
        }
    }

    eprintln!("vosx: running...\n");

    loop {
        match sched.tick() {
            TickResult::Progress => {}
            TickResult::Idle => {
                eprintln!("\nvosx: all services idle, exiting");
                break;
            }
            TickResult::Done => {
                eprintln!("\nvosx: all services done");
                break;
            }
        }
    }
}
