//! Kunekt manifest — defines a set of services to run together.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub manifest: ManifestMeta,
    #[serde(rename = "actors")]
    pub actors: Vec<ServiceDef>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestMeta {
    pub name: String,
    #[serde(default = "default_gas")]
    pub gas: u64,
}

fn default_gas() -> u64 {
    1_000_000
}

#[derive(Debug, Deserialize)]
pub struct ServiceDef {
    pub name: String,
    pub path: Option<PathBuf>,
    pub source: Option<String>,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "elf".to_string()
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ManifestError::Io(path.to_path_buf(), e))?;
        let manifest: Self =
            toml::from_str(&content).map_err(ManifestError::Parse)?;
        Ok(manifest)
    }
}

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
