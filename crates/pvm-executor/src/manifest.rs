//! Kunekt manifest — defines a set of actors to run together.
//!
//! A `Kunekt.toml` file lists actor programs by path (to RISC-V ELF files)
//! or by name (from a future registry). The `kunekt` binary reads this
//! manifest, transpiles ELFs to PVM blobs, and runs the actors cooperatively.
//!
//! ```toml
//! [manifest]
//! name = "my-app"
//! gas = 1000000          # optional, default gas per tick
//!
//! [[actors]]
//! name = "counter"
//! path = "./target/riscv64em-unknown-none-elf/release/counter"
//!
//! [[actors]]
//! name = "logger"
//! path = "./actors/logger.elf"
//! ```

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level manifest structure.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub manifest: ManifestMeta,
    #[serde(rename = "actors")]
    pub actors: Vec<ActorDef>,
}

/// Manifest metadata.
#[derive(Debug, Deserialize)]
pub struct ManifestMeta {
    pub name: String,
    /// Default gas budget per actor per tick.
    #[serde(default = "default_gas")]
    pub gas: u64,
}

fn default_gas() -> u64 {
    1_000_000
}

/// An actor definition in the manifest.
#[derive(Debug, Deserialize)]
pub struct ActorDef {
    /// Human-readable name for this actor.
    pub name: String,
    /// Path to the RISC-V ELF binary (resolved relative to the manifest).
    pub path: Option<PathBuf>,
    /// Future: registry source (e.g. "kunekt-registry:counter@1.0").
    pub source: Option<String>,
}

impl Manifest {
    /// Load a manifest from a TOML file.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ManifestError::Io(path.to_path_buf(), e))?;
        let manifest: Self =
            toml::from_str(&content).map_err(ManifestError::Parse)?;
        Ok(manifest)
    }
}

/// Errors that can occur loading a manifest.
#[derive(Debug)]
pub enum ManifestError {
    Io(PathBuf, std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(path, e) => write!(f, "reading {}: {}", path.display(), e),
            ManifestError::Parse(e) => write!(f, "parsing manifest: {e}"),
        }
    }
}
