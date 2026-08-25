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
    0x63, 0x82, 0x8f, 0x5c, 0xbe, 0x1b, 0x37, 0x96, 0xe0, 0x52, 0x01, 0xc4, 0xb8, 0x03, 0x98, 0x46,
    0x40, 0x50, 0x6b, 0x1f, 0xaa, 0x45, 0xe9, 0xbd, 0xcd, 0xdb, 0x84, 0x63, 0x0c, 0x9f, 0x27, 0x87,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0xc7, 0xb7, 0xe2, 0x7b, 0x3e, 0x5f, 0x77, 0x5d, 0xe0, 0x65, 0x91, 0xa5, 0x1e, 0x7c, 0xbc, 0xf1,
    0xbd, 0x20, 0xa0, 0xc9, 0xa4, 0x07, 0x49, 0x38, 0xb7, 0x27, 0x55, 0x89, 0x2a, 0xad, 0x0f, 0x3f,
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
