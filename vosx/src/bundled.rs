//! Build-time-bundled PVM actor ELFs.
//!
//! Two platform actors are bundled:
//!
//! - **space-registry**: per-space program/agent/member catalog.
//!   Required for every `vosx space new` / `space up <token>`; without it
//!   those commands have to take a `--registry` source explicitly.
//! - **space-authority**: canonical actor PVM used to construct the root-signed
//!   authority package at first service startup. Package signing remains local to
//!   the immutable space root.
//!
//! `build.rs` loads the checked release blobs and verifies their pinned
//! digests. Developer target directories are never selected implicitly.

const BUNDLED_REGISTRY_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_REGISTRY_ELF"));
const BUNDLED_SPACE_AUTHORITY_PVM: &[u8] = include_bytes!(env!("VOSX_BUNDLED_SPACE_AUTHORITY_PVM"));

/// Canonical authority identity. These runtime pins are shared by the
/// release packager and verifier; build.rs independently checks the raw digest
/// before the bytes can be embedded in this binary.
pub(crate) const SPACE_AUTHORITY_PROGRAM_ID: [u8; 32] = [
    0x2c, 0xf4, 0x6b, 0xcc, 0x48, 0x4a, 0x9a, 0xf8, 0xa7, 0x15, 0xb1, 0xec, 0x4d, 0x62, 0x8f, 0xf1,
    0x64, 0x4d, 0xcd, 0x34, 0x04, 0xb4, 0x59, 0x1a, 0xcb, 0xfd, 0xcb, 0xe1, 0x35, 0xf7, 0x90, 0x60,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x29, 0xa2, 0x48, 0xa9, 0x8b, 0x50, 0x9c, 0x0e, 0x96, 0x95, 0x45, 0x54, 0x70, 0x48, 0xe0, 0x18,
    0xca, 0x2b, 0xe4, 0x2f, 0x7a, 0xf7, 0xc8, 0x79, 0x6f, 0x77, 0x42, 0xdc, 0x0b, 0x3f, 0xad, 0xb8,
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
