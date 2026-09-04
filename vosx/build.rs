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
}

const SPACE_REGISTRY_BLAKE2B_256: [u8; 32] = [
    0xb5, 0xee, 0x80, 0x96, 0x93, 0xf9, 0x15, 0xfa, 0x2d, 0x3e, 0x3c, 0x3b, 0x88, 0x02, 0xaf, 0xc8,
    0x67, 0x1a, 0xf2, 0x92, 0x45, 0xdb, 0xab, 0x3e, 0xf7, 0x8d, 0xfb, 0x85, 0xbe, 0x83, 0x21, 0xf1,
];
const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0xd5, 0x94, 0x55, 0xd2, 0xf6, 0x38, 0x11, 0x9a, 0xd4, 0xa3, 0xa6, 0xa8, 0xe1, 0x27, 0xd8, 0x4a,
    0x0d, 0xad, 0x87, 0xd7, 0x9d, 0xe3, 0x20, 0xa7, 0x88, 0xf5, 0x78, 0x3a, 0xad, 0x17, 0xb5, 0x01,
];
const AGENT_RUNTIME_BLAKE2B_256: [u8; 32] = [
    0xab, 0x63, 0xc0, 0x8f, 0x6a, 0x43, 0xe3, 0x27, 0x0e, 0xab, 0x1d, 0x99, 0x53, 0x0a, 0x68, 0x21,
    0x9d, 0x9d, 0x9e, 0x28, 0x52, 0x67, 0x2f, 0xe1, 0x7e, 0xd0, 0x37, 0xc6, 0x5e, 0xf6, 0x04, 0x8b,
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
