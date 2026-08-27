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
