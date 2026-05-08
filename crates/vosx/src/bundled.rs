//! Build-time-bundled space-registry actor ELF.
//!
//! Populated by `build.rs` from the space-registry crate's
//! `target/riscv64em-javm/release/space-registry-actor.elf`.
//! When that file isn't present at vosx-build time, the
//! bundle is empty and the runtime falls back to requiring
//! `--registry` from the user.

const BUNDLED_REGISTRY_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_REGISTRY_ELF"));

/// Returns the bundled space-registry ELF bytes, or `None` if
/// vosx was built without the actor pre-built.
pub fn registry_elf() -> Option<&'static [u8]> {
    if BUNDLED_REGISTRY_ELF.is_empty() {
        None
    } else {
        Some(BUNDLED_REGISTRY_ELF)
    }
}
