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
    0x01, 0x1f, 0xbc, 0xc1, 0x88, 0x88, 0x0d, 0x9e, 0xf8, 0xcb, 0xce, 0xad, 0xd5, 0x22, 0x51, 0x9d,
    0xa6, 0xae, 0xd4, 0x10, 0xcf, 0x60, 0xdd, 0xa2, 0x44, 0x86, 0xba, 0x00, 0xe4, 0x2f, 0xc5, 0x0e,
];
const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0xb4, 0x2e, 0x12, 0xa7, 0xa6, 0xbb, 0xaa, 0x06, 0x29, 0x14, 0xad, 0xf3, 0xaa, 0x23, 0xab, 0x83,
    0x1e, 0x8e, 0xf8, 0x53, 0x4f, 0x75, 0x7d, 0x2c, 0xa0, 0x5a, 0xf3, 0x5a, 0x34, 0x4e, 0x4f, 0x45,
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
