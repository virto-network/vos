//! Bundles pre-built platform actors into the vosx binary.
//!
//! Registry and authority bytes are durable protocol identities. Both are
//! loaded only from committed release blobs and checked against pinned
//! digests. A source build is an explicit repin candidate, never an implicit
//! replacement selected from a developer target directory.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    bundle_frozen_artifact(
        &manifest_dir,
        &out_dir,
        "space_registry.elf",
        "bundled_registry.elf",
        "VOSX_BUNDLED_REGISTRY_ELF",
        &SPACE_REGISTRY_BLAKE2B_256,
        "space-registry",
    );
    bundle_frozen_artifact(
        &manifest_dir,
        &out_dir,
        "space_authority.pvm",
        "bundled_space_authority.pvm",
        "VOSX_BUNDLED_SPACE_AUTHORITY_PVM",
        &SPACE_AUTHORITY_BLAKE2B_256,
        "space-authority",
    );
}

const SPACE_REGISTRY_BLAKE2B_256: [u8; 32] = [
    0xc2, 0x65, 0xf5, 0x0a, 0x90, 0x31, 0xea, 0xb4, 0xc1, 0x1f, 0x1c, 0xa2, 0x6e, 0x25, 0x0e, 0xbb,
    0x55, 0xa5, 0xad, 0x89, 0xb2, 0x11, 0xf4, 0x50, 0x33, 0x26, 0xa9, 0xf7, 0xa2, 0xf0, 0x3e, 0x94,
];
const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x4a, 0xee, 0x04, 0x01, 0xf1, 0x96, 0x94, 0x9e, 0xbb, 0x6a, 0xbf, 0xdc, 0xb2, 0xd7, 0x7f, 0x1c,
    0x31, 0x84, 0x40, 0x6d, 0x0b, 0xa1, 0x67, 0x12, 0x7a, 0xf2, 0xfb, 0x6e, 0x45, 0x64, 0x35, 0x83,
];

fn bundle_frozen_artifact(
    manifest_dir: &Path,
    out_dir: &Path,
    file: &str,
    bundled_file: &str,
    env_var: &str,
    expected_digest: &[u8; 32],
    label: &str,
) {
    let source = manifest_dir.join("blobs").join(file);
    let bytes = fs::read(&source).unwrap_or_else(|e| {
        panic!(
            "read canonical {label} {}: {e}; restore the committed release blob",
            source.display()
        )
    });
    let digest = blake2b_simd::Params::new().hash_length(32).hash(&bytes);
    assert_eq!(
        digest.as_bytes(),
        expected_digest,
        "canonical {label} {} does not match its release digest; use the explicit repin workflow",
        source.display(),
    );

    let dest = out_dir.join(bundled_file);
    fs::write(&dest, &bytes).unwrap_or_else(|e| panic!("write {bundled_file}: {e}"));
    println!(
        "cargo:warning=vosx: bundled canonical {label} ({} bytes) from {}",
        bytes.len(),
        source.display(),
    );
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rustc-env={env_var}={}", dest.display());
}
