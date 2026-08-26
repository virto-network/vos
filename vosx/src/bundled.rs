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
    0xa5, 0xd4, 0xef, 0xeb, 0xf5, 0xc0, 0xf3, 0xdb, 0xea, 0x9f, 0x04, 0x3a, 0x32, 0xfc, 0x2b, 0xfb,
    0xa5, 0xa9, 0x6a, 0xaa, 0xbb, 0x7f, 0x32, 0x26, 0xb4, 0x1c, 0x73, 0xf5, 0x13, 0xdb, 0x1a, 0x24,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0x4a, 0xee, 0x04, 0x01, 0xf1, 0x96, 0x94, 0x9e, 0xbb, 0x6a, 0xbf, 0xdc, 0xb2, 0xd7, 0x7f, 0x1c,
    0x31, 0x84, 0x40, 0x6d, 0x0b, 0xa1, 0x67, 0x12, 0x7a, 0xf2, 0xfb, 0x6e, 0x45, 0x64, 0x35, 0x83,
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
