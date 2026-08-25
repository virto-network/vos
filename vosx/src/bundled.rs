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
    0x48, 0x79, 0x2b, 0x3f, 0xb5, 0x77, 0x72, 0xec, 0x76, 0xdd, 0xcb, 0x5d, 0xd9, 0x85, 0xcc, 0x7d,
    0x14, 0xf8, 0x7a, 0x82, 0x08, 0x14, 0xe4, 0x04, 0x0a, 0x60, 0x12, 0xee, 0xf9, 0x24, 0xc6, 0x72,
];
pub(crate) const SPACE_AUTHORITY_BLAKE2B_256: [u8; 32] = [
    0xb4, 0x2e, 0x12, 0xa7, 0xa6, 0xbb, 0xaa, 0x06, 0x29, 0x14, 0xad, 0xf3, 0xaa, 0x23, 0xab, 0x83,
    0x1e, 0x8e, 0xf8, 0x53, 0x4f, 0x75, 0x7d, 0x2c, 0xa0, 0x5a, 0xf3, 0x5a, 0x34, 0x4e, 0x4f, 0x45,
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
