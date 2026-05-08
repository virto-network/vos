//! Bundles the pre-built space-registry actor ELF into the vosx
//! binary so `space new` / `space join` work out of the box
//! without `--registry`.
//!
//! The bundled blob is sourced from
//! `crates/actors/space-registry/target/riscv64em-javm/release/space-registry-actor.elf`,
//! produced by `cargo actor` in that crate's directory. If the
//! ELF doesn't exist, build.rs writes an empty placeholder so
//! the runtime `include_bytes!` always succeeds; `space new`
//! falls back to requiring `--registry` and prints a helpful
//! message pointing at the build step.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Track manifest dir → workspace → space-registry crate's
    // expected output. `CARGO_MANIFEST_DIR` is `crates/vosx/`.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let elf_path = manifest_dir
        .join("..")
        .join("actors")
        .join("space-registry")
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("space_registry.elf");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("bundled_registry.elf");

    match fs::read(&elf_path) {
        Ok(bytes) => {
            fs::write(&dest, &bytes).expect("write bundled_registry.elf");
            println!("cargo:rerun-if-changed={}", elf_path.display());
            println!(
                "cargo:warning=vosx: bundled space-registry ({} bytes) from {}",
                bytes.len(),
                elf_path.display(),
            );
        }
        Err(_) => {
            // Empty placeholder — `include_bytes!` still resolves;
            // runtime detects empty and falls back.
            fs::write(&dest, []).expect("write empty bundled_registry.elf");
            println!(
                "cargo:warning=vosx: space-registry not built — `space new`/`space join` will require --registry. \
                 To enable bundling: cd crates/actors/space-registry && cargo actor"
            );
        }
    }

    // Force re-run when the elf appears or changes.
    println!("cargo:rerun-if-changed={}", elf_path.display());
    println!("cargo:rustc-env=VOSX_BUNDLED_REGISTRY_ELF={}", dest.display());
}
