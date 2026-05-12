//! Bundles the pre-built space-registry actor ELF into the vosx
//! binary so `space new` / `space join` work out of the box
//! without `--registry`.
//!
//! Two source paths, tried in order:
//!
//! 1. **Dev path**: `actors/space-registry/target/riscv64em-javm/release/space_registry.elf`,
//!    produced by `cargo actor` in that crate's directory. Inside
//!    this workspace it's the fresh build; consumed by working-tree
//!    builds and tests so changes show up immediately.
//! 2. **Shipped path**: `vosx/blobs/space_registry.elf`. This file
//!    is checked into the crate so `cargo package` includes it,
//!    which is what `cargo install vosx` from crates.io uses.
//!
//! In a working tree both paths typically exist; the dev path wins
//! because it's where local rebuilds land. In a packaged crate only
//! the shipped path exists. If neither file is present, build.rs
//! writes an empty placeholder so the runtime `include_bytes!`
//! always resolves; `space new` falls back to requiring `--registry`
//! and prints a helpful message pointing at the build step.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let dev_path = manifest_dir
        .join("..")
        .join("actors")
        .join("space-registry")
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("space_registry.elf");

    let shipped_path = manifest_dir.join("blobs").join("space_registry.elf");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("bundled_registry.elf");

    let bundled = read_first_present(&[dev_path.as_path(), shipped_path.as_path()]);

    match bundled {
        Some((source, bytes)) => {
            fs::write(&dest, &bytes).expect("write bundled_registry.elf");
            println!(
                "cargo:warning=vosx: bundled space-registry ({} bytes) from {}",
                bytes.len(),
                source.display(),
            );
        }
        None => {
            // Empty placeholder — `include_bytes!` still resolves;
            // runtime detects empty and falls back.
            fs::write(&dest, []).expect("write empty bundled_registry.elf");
            println!(
                "cargo:warning=vosx: space-registry not built — `space new`/`space join` will require --registry. \
                 To enable bundling: cd actors/space-registry && cargo actor"
            );
        }
    }

    // Force re-run when either source path appears or changes.
    println!("cargo:rerun-if-changed={}", dev_path.display());
    println!("cargo:rerun-if-changed={}", shipped_path.display());
    println!(
        "cargo:rustc-env=VOSX_BUNDLED_REGISTRY_ELF={}",
        dest.display()
    );
}

fn read_first_present(candidates: &[&Path]) -> Option<(PathBuf, Vec<u8>)> {
    for p in candidates {
        if let Ok(bytes) = fs::read(p) {
            return Some((p.to_path_buf(), bytes));
        }
    }
    None
}
