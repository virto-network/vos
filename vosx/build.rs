//! Bundles pre-built platform actors into the vosx binary.
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
//!
//! The canonical space authority is deliberately different: its bytes
//! are a durable protocol identity sealed into existing spaces. It is
//! always loaded from the committed release blob and checked against its
//! frozen digest. A source rebuild is an upgrade candidate, never an
//! implicit replacement for that identity.

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

    bundle_frozen_space_authority(&manifest_dir, &out_dir);
}

const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x86, 0x87, 0x2e, 0x83, 0xd3, 0xbb, 0x44, 0x5c, 0xbf, 0x2b, 0x47, 0x7e, 0x81, 0xd5, 0x1a, 0xaa,
    0xa5, 0xc2, 0x1e, 0x0a, 0x75, 0x55, 0xe9, 0x02, 0x26, 0x00, 0x0d, 0x09, 0xae, 0xca, 0x08, 0x42,
];

/// Bundle the release authority identity without consulting developer output.
/// Existing sealed spaces derive their canonical authority incarnation from
/// these exact bytes, so silently preferring a newer local build would make
/// them impossible to reopen.
fn bundle_frozen_space_authority(manifest_dir: &Path, out_dir: &Path) {
    let source = manifest_dir.join("blobs/space_authority.pvm");
    let bytes = fs::read(&source).unwrap_or_else(|e| {
        panic!(
            "read frozen canonical authority {}: {e}; restore the committed release blob",
            source.display()
        )
    });
    let digest = blake2b_simd::Params::new().hash_length(32).hash(&bytes);
    assert_eq!(
        digest.as_bytes(),
        SPACE_AUTHORITY_BLAKE2B_256,
        "frozen canonical authority {} does not match its release digest; source rebuilds must use the explicit UpgradeActor path",
        source.display(),
    );

    let dest = out_dir.join("bundled_space_authority.pvm");
    fs::write(&dest, &bytes).unwrap_or_else(|e| panic!("write bundled_space_authority.pvm: {e}"));
    println!(
        "cargo:warning=vosx: bundled frozen space-authority ({} bytes) from {}",
        bytes.len(),
        source.display(),
    );
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rustc-env=VOSX_BUNDLED_SPACE_AUTHORITY_PVM={}",
        dest.display()
    );
}

/// Wire up one bundled actor artifact. Tries the working-tree dev path
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
