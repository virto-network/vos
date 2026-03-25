//! `kunekt` — run a manifest of PVM actors cooperatively.
//!
//! Usage:
//!     kunekt [path/to/Kunekt.toml]
//!
//! If no path is given, looks for `Kunekt.toml` in the current directory.
//!
//! The binary:
//! 1. Reads the manifest to discover actor ELF paths
//! 2. Transpiles each RISC-V ELF to a PVM blob using grey-transpiler
//! 3. Loads all actors into the PVM executor
//! 4. Runs the cooperative scheduler until all actors complete

use pvm_executor::manifest::Manifest;
use pvm_executor::pvm_driver::{PvmDriver, RawMsg};
use pvm_executor::scheduler::{Scheduler, TickResult};
use std::path::PathBuf;
use std::process;

fn main() {
    let manifest_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("Kunekt.toml"));

    eprintln!("kunekt: loading {}", manifest_path.display());

    let manifest = match Manifest::load(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "kunekt: manifest '{}' — {} actor(s)",
        manifest.manifest.name,
        manifest.actors.len()
    );

    let manifest_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut driver = PvmDriver::new();
    let mut blob_indices = Vec::new();

    // Transpile and register each actor
    for actor_def in &manifest.actors {
        let elf_path = match &actor_def.path {
            Some(p) => manifest_dir.join(p),
            None => {
                eprintln!(
                    "error: actor '{}' has no path (registry not yet supported)",
                    actor_def.name
                );
                process::exit(1);
            }
        };

        eprintln!("  transpiling '{}' from {}", actor_def.name, elf_path.display());

        let elf_data = match std::fs::read(&elf_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: reading {}: {e}", elf_path.display());
                process::exit(1);
            }
        };

        let pvm_blob = match grey_transpiler::link_elf(&elf_data) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: transpiling '{}': {e:?}", actor_def.name);
                process::exit(1);
            }
        };

        let blob_idx = driver.register_blob(pvm_blob);
        blob_indices.push((actor_def.name.clone(), blob_idx));
    }

    // Create the scheduler and spawn actors
    let mut sched: Scheduler<RawMsg, PvmDriver, 64, 16> = Scheduler::new(driver);

    for (name, blob_idx) in &blob_indices {
        match sched.spawn() {
            Some(id) => {
                let status = sched.driver_mut().spawn_blob(id, *blob_idx);
                eprintln!("  spawned '{name}' as actor {id:?} — {status:?}");
            }
            None => {
                eprintln!("error: too many actors");
                process::exit(1);
            }
        }
    }

    eprintln!("kunekt: running...\n");

    // Run the cooperative scheduler
    loop {
        match sched.tick() {
            TickResult::Progress => {}
            TickResult::Idle => {
                // All actors idle — in a real system we'd wait for
                // external events. For now, just exit.
                eprintln!("\nkunekt: all actors idle, exiting");
                break;
            }
            TickResult::Done => {
                eprintln!("\nkunekt: all actors done");
                break;
            }
        }
    }
}
