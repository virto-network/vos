//! Bundles the pre-built space-registry actor ELF into the vosx
//! binary so `space new` / `space up <token>` work out of the box
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
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bundle_actor(
        &manifest_dir,
        &out_dir,
        "space-registry",
        "space_registry.elf",
        "bundled_registry.elf",
        "VOSX_BUNDLED_REGISTRY_ELF",
        "`space new`/`space up <token>` will require --registry",
        "cd actors/space-registry && cargo actor",
    );

    bundle_actor(
        &manifest_dir,
        &out_dir,
        "dev-project",
        "dev_project.elf",
        "bundled_dev_project.elf",
        "VOSX_BUNDLED_DEV_PROJECT_ELF",
        "`dev new` will require --program-source",
        "cd actors/dev-project && cargo actor",
    );
}

/// Wire up one bundled actor ELF. Tries the working-tree dev path
/// first (live rebuilds win) and falls back to the shipped
/// `blobs/<file>` (what `cargo package` ships from crates.io). If
/// neither exists, writes an empty placeholder and prints a hint
/// at how to populate the bundle.
#[allow(clippy::too_many_arguments)]
fn bundle_actor(
    manifest_dir: &Path,
    out_dir: &Path,
    actor_dir: &str,
    elf_filename: &str,
    bundled_dest: &str,
    env_var: &str,
    missing_hint: &str,
    build_cmd: &str,
) {
    let dev_path = manifest_dir
        .join("..")
        .join("actors")
        .join(actor_dir)
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join(elf_filename);
    let shipped_path = manifest_dir.join("blobs").join(elf_filename);
    let dest = out_dir.join(bundled_dest);

    let bundled = read_first_present(&[dev_path.as_path(), shipped_path.as_path()]);
    match bundled {
        Some((source, bytes)) => {
            fs::write(&dest, &bytes).unwrap_or_else(|e| panic!("write {bundled_dest}: {e}"));
            println!(
                "cargo:warning=vosx: bundled {actor_dir} ({} bytes) from {}",
                bytes.len(),
                source.display(),
            );
        }
        None => {
            fs::write(&dest, []).unwrap_or_else(|e| panic!("write empty {bundled_dest}: {e}"));
            println!(
                "cargo:warning=vosx: {actor_dir} not built — {missing_hint}. \
                 To enable bundling: {build_cmd}"
            );
        }
    }

    println!("cargo:rerun-if-changed={}", dev_path.display());
    println!("cargo:rerun-if-changed={}", shipped_path.display());
    println!("cargo:rustc-env={env_var}={}", dest.display());
}

fn read_first_present(candidates: &[&Path]) -> Option<(PathBuf, Vec<u8>)> {
    for p in candidates {
        if let Ok(bytes) = fs::read(p) {
            return Some((p.to_path_buf(), bytes));
        }
    }
    None
}
