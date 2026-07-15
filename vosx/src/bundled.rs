//! Build-time-bundled PVM actor ELFs.
//!
//! Two actors get bundled today:
//!
//! - **space-registry**: per-space program/agent/member catalog.
//!   Required for every `vosx space new` / `space up <token>`; without it
//!   those commands have to take a `--registry` source explicitly.
//! - **dev-project**: per-project content-addressed object store +
//!   commit DAG. Backing actor for the dev extension's compile /
//!   publish flow; bundled so `vosx dev new` can publish + install
//!   the program in one shot without out-of-band scaffolding.
//!
//! `build.rs` prefers the working-tree path under
//! `actors/<name>/target/riscv64em-javm/release/` and falls back to
//! `vosx/blobs/<name>.elf` (checked into the crate). When neither
//! is present the bundle is empty and the runtime falls back to
//! requiring an explicit `--registry` / `--program-source` arg
//! depending on which one is missing.

const BUNDLED_REGISTRY_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_REGISTRY_ELF"));
const BUNDLED_DEV_PROJECT_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_DEV_PROJECT_ELF"));

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
