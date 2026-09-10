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
    0x42, 0x6d, 0xf6, 0xa5, 0x4f, 0x25, 0x04, 0x80, 0xd5, 0x6b, 0x12, 0xfa, 0x7a, 0xc9, 0xa6, 0xc7,
    0xea, 0xdf, 0xb8, 0xd2, 0xc0, 0x33, 0x51, 0xcf, 0xd2, 0x43, 0x3c, 0xa9, 0x85, 0x86, 0x01, 0x2c,
];
const SYSTEM_AUTHORITY_PACKAGE_BLAKE2B_256: [u8; 32] = [
    0xee, 0x9a, 0x17, 0x29, 0x99, 0x18, 0xf0, 0x29, 0x74, 0x89, 0x70, 0x2e, 0x84, 0x8a, 0x96, 0xfd,
    0x8a, 0x56, 0x57, 0x7b, 0x03, 0xb3, 0x6a, 0xb3, 0xb0, 0xe4, 0x29, 0xfb, 0x14, 0x84, 0xaf, 0x77,
];
const SYSTEM_CATALOG_PACKAGE_BLAKE2B_256: [u8; 32] = [
    0x5f, 0x45, 0x5a, 0x9b, 0x64, 0x78, 0x42, 0x4c, 0x17, 0xc2, 0x33, 0xf3, 0x94, 0xfd, 0x9a, 0x0f,
    0xac, 0x0b, 0x4f, 0x9e, 0xc3, 0x3f, 0x06, 0x95, 0x6d, 0xa5, 0x45, 0xa3, 0x9e, 0xc2, 0xf2, 0x78,
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
