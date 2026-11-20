//! What the light node's test binaries share: the release artifacts from
//! this tree's guests, and a device's light node with one local actor
//! installed.

#![allow(dead_code)]

pub mod device;

use std::path::PathBuf;
use std::sync::OnceLock;

use vos_light::release::{self, Package};
use vos_testkit::programs;

/// The default agent program, linked, as the release build computes it.
pub fn agent() -> &'static [u8] {
    static AGENT: OnceLock<Vec<u8>> = OnceLock::new();
    AGENT.get_or_init(|| {
        release::agent(&std::fs::read(programs::program_elf("vos-agent")).unwrap()).unwrap()
    })
}

/// The package of the guest at `elf`, as its release `release`.
pub fn package(elf: PathBuf, release: u32) -> Package {
    release::package(&std::fs::read(elf).unwrap(), release).unwrap()
}

/// The notes actor's package, its first release.
pub fn notes() -> &'static Package {
    static NOTES: OnceLock<Package> = OnceLock::new();
    NOTES.get_or_init(|| package(programs::actor_elf("notes"), 1))
}
