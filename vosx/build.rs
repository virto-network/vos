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
    0x22, 0x0d, 0x02, 0xcd, 0x2b, 0xa2, 0x02, 0x11, 0x86, 0x88, 0x37, 0xd3, 0x0a, 0x48, 0xee, 0x9d,
    0x3b, 0x11, 0x58, 0xba, 0xcc, 0x82, 0x15, 0x8e, 0x02, 0x4d, 0xef, 0x73, 0x13, 0x58, 0x7e, 0x01,
];
const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x91, 0x33, 0x14, 0xbb, 0x84, 0x19, 0x11, 0x56, 0x6b, 0x20, 0x8f, 0xa0, 0xa9, 0x3a, 0xca, 0x0c,
    0xd8, 0x2e, 0x53, 0xd3, 0x10, 0xed, 0xd6, 0xb2, 0xf3, 0xd6, 0xf6, 0xc7, 0xf3, 0xeb, 0x42, 0x61,
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
