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
    bundle_frozen_artifact(
        &manifest_dir,
        &out_dir,
        "agent_runtime.pvm",
        "bundled_agent_runtime.pvm",
        "VOSX_BUNDLED_AGENT_RUNTIME_PVM",
        &AGENT_RUNTIME_BLAKE2B_256,
        "agent-runtime",
    );
    bundle_frozen_artifact(
        &manifest_dir,
        &out_dir,
        "system_authority.vos",
        "bundled_system_authority.vos",
        "VOSX_BUNDLED_SYSTEM_AUTHORITY_PACKAGE",
        &SYSTEM_AUTHORITY_PACKAGE_BLAKE2B_256,
        "system-authority package template",
    );
    bundle_frozen_artifact(
        &manifest_dir,
        &out_dir,
        "system_catalog.vos",
        "bundled_system_catalog.vos",
        "VOSX_BUNDLED_SYSTEM_CATALOG_PACKAGE",
        &SYSTEM_CATALOG_PACKAGE_BLAKE2B_256,
        "system-catalog package template",
    );
}

const SPACE_REGISTRY_BLAKE2B_256: [u8; 32] = [
    0x46, 0x1f, 0x2b, 0x36, 0x8d, 0xd6, 0x53, 0x69, 0x8c, 0x86, 0x50, 0xb0, 0x78, 0x00, 0xb8, 0x16,
    0x34, 0xb3, 0x07, 0x2b, 0x37, 0xfd, 0x7a, 0x5f, 0x37, 0x08, 0x58, 0x10, 0x21, 0xbb, 0xbd, 0x32,
];
const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0xf9, 0x1f, 0x99, 0x3d, 0xd4, 0x59, 0xa6, 0xa8, 0x10, 0x7b, 0x85, 0xdc, 0x3a, 0x0b, 0x12, 0x77,
    0x61, 0x91, 0xfa, 0xaf, 0x9c, 0xab, 0x49, 0x4a, 0x44, 0x3d, 0x12, 0xb9, 0x2c, 0x74, 0x5a, 0xc6,
];
const AGENT_RUNTIME_BLAKE2B_256: [u8; 32] = [
    0xa7, 0x64, 0x1e, 0x7d, 0xfe, 0xe9, 0xbf, 0xf3, 0x9e, 0x45, 0x03, 0xfd, 0xe1, 0x11, 0x91, 0x1a,
    0x3b, 0xf6, 0x3c, 0x1e, 0x87, 0x2b, 0x27, 0xcd, 0x4a, 0x1c, 0x9c, 0x89, 0x56, 0x53, 0x44, 0x2a,
];
const SYSTEM_AUTHORITY_PACKAGE_BLAKE2B_256: [u8; 32] = [
    0xd0, 0x9e, 0x65, 0x71, 0x8f, 0x32, 0xfd, 0xc2, 0x54, 0xc3, 0x84, 0xa4, 0xde, 0x08, 0x5e, 0x20,
    0x94, 0x16, 0x55, 0xd0, 0x21, 0xb1, 0xf8, 0x45, 0x32, 0xd1, 0xce, 0xa4, 0xe2, 0xaa, 0xf0, 0x7c,
];
const SYSTEM_CATALOG_PACKAGE_BLAKE2B_256: [u8; 32] = [
    0x3a, 0xed, 0x35, 0x47, 0x47, 0x1e, 0x58, 0xea, 0x56, 0x71, 0xed, 0x9d, 0xc2, 0x09, 0xdd, 0xc0,
    0x79, 0x36, 0x5d, 0x85, 0x48, 0x7d, 0x8b, 0x8d, 0x4e, 0xa6, 0xd5, 0x74, 0xba, 0x23, 0xaf, 0xe6,
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
