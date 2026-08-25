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

/// Canonical ABI-17 authority identity. These runtime pins are shared by the
/// release packager and verifier; build.rs independently checks the raw digest
/// before the bytes can be embedded in this binary.
pub(crate) const SPACE_AUTHORITY_PROGRAM_ID: [u8; 32] = [
    0x79, 0x09, 0x9c, 0xcb, 0xec, 0x4e, 0x4d, 0xac, 0x7a, 0xf8, 0x93, 0xe1, 0x53, 0xba, 0x37, 0x9a,
    0x1d, 0x33, 0xaa, 0x75, 0x73, 0x4d, 0xaf, 0x1d, 0x93, 0xcb, 0xba, 0x3e, 0x68, 0x4d, 0x65, 0xeb,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x45, 0xc1, 0xe7, 0x5b, 0xeb, 0x82, 0x1b, 0x45, 0xa2, 0x24, 0x2f, 0xd7, 0x30, 0xc7, 0x29, 0xa1,
    0x9f, 0xab, 0x01, 0x4b, 0xe1, 0x43, 0x8a, 0xe2, 0x93, 0xdf, 0x19, 0x37, 0x49, 0x2e, 0xfe, 0xbc,
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
