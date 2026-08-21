//! Build-time-bundled PVM actor ELFs.
//!
//! Three actors get bundled today:
//!
//! - **space-registry**: per-space program/agent/member catalog.
//!   Required for every `vosx space new` / `space up <token>`; without it
//!   those commands have to take a `--registry` source explicitly.
//! - **dev-project**: per-project content-addressed object store +
//!   commit DAG. Backing actor for the dev extension's compile /
//!   publish flow; bundled so `vosx dev new` can publish + install
//!   the program in one shot without out-of-band scaffolding.
//! - **space-authority**: canonical actor PVM used to construct the root-signed
//!   authority package at first v2 startup. Package signing remains local to
//!   the immutable space root.
//!
//! `build.rs` prefers the working-tree path under
//! `actors/<name>/target/riscv64em-javm/release/` and falls back to
//! `vosx/blobs/<name>.elf` (checked into the crate). When neither
//! is present the bundle is empty and the runtime falls back to
//! requiring an explicit `--registry` / `--program-source` arg
//! depending on which one is missing.

const BUNDLED_REGISTRY_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_REGISTRY_ELF"));
const BUNDLED_DEV_PROJECT_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_DEV_PROJECT_ELF"));
const BUNDLED_SPACE_AUTHORITY_PVM: &[u8] = include_bytes!(env!("VOSX_BUNDLED_SPACE_AUTHORITY_PVM"));

/// Frozen Batch-70 authority identity. These runtime pins are shared by the
/// release packager and verifier; build.rs independently checks the raw digest
/// before the bytes can be embedded in this binary.
pub(crate) const SPACE_AUTHORITY_PROGRAM_ID: [u8; 32] = [
    0x16, 0xd0, 0x48, 0x8c, 0xd5, 0x1b, 0xfb, 0x70, 0xf5, 0x69, 0x7c, 0xb9, 0x09, 0xc7, 0xeb, 0x2a,
    0x76, 0x77, 0x26, 0x73, 0x93, 0x6f, 0x3d, 0xb6, 0x9f, 0xf3, 0x96, 0x86, 0x8f, 0x77, 0x13, 0xe3,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x86, 0x87, 0x2e, 0x83, 0xd3, 0xbb, 0x44, 0x5c, 0xbf, 0x2b, 0x47, 0x7e, 0x81, 0xd5, 0x1a, 0xaa,
    0xa5, 0xc2, 0x1e, 0x0a, 0x75, 0x55, 0xe9, 0x02, 0x26, 0x00, 0x0d, 0x09, 0xae, 0xca, 0x08, 0x42,
];

/// Returns the bundled space-registry ELF bytes, or `None` if
/// vosx was built without the actor pre-built.
pub fn registry_elf() -> Option<&'static [u8]> {
    // `BUNDLED_REGISTRY_ELF` is `&[u8; N]` from `include_bytes!`, so
    // clippy sees this length check as a const-false; in practice
    // build.rs writes either the actor bytes or an empty placeholder
    // and we have to discriminate at runtime.
    #[allow(clippy::const_is_empty)]
    if BUNDLED_REGISTRY_ELF.is_empty() {
        None
    } else {
        Some(BUNDLED_REGISTRY_ELF)
    }
}

/// Returns the bundled dev-project ELF bytes, or `None` if vosx
/// was built without the actor pre-built. Used by `vosx dev new`
/// to provision a project actor instance without requiring the
/// operator to publish the dev-project program manually first.
pub fn dev_project_elf() -> Option<&'static [u8]> {
    #[allow(clippy::const_is_empty)]
    if BUNDLED_DEV_PROJECT_ELF.is_empty() {
        None
    } else {
        Some(BUNDLED_DEV_PROJECT_ELF)
    }
}

/// Returns the canonical space-authority PVM bytes, or `None` when a
/// development build omitted the checked infrastructure artifact.
pub fn space_authority_pvm() -> Option<&'static [u8]> {
    #[allow(clippy::const_is_empty)]
    if BUNDLED_SPACE_AUTHORITY_PVM.is_empty() {
        None
    } else {
        Some(BUNDLED_SPACE_AUTHORITY_PVM)
    }
}
