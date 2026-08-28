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
    0x29, 0xa7, 0xc4, 0xfa, 0x69, 0x5f, 0xad, 0x9c, 0x59, 0x5b, 0x20, 0x4e, 0xcd, 0xda, 0xf4, 0xea,
    0x2a, 0x89, 0x7b, 0x30, 0x03, 0x72, 0xc8, 0xff, 0x44, 0x97, 0xa5, 0x6d, 0x82, 0x96, 0xe4, 0x33,
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
