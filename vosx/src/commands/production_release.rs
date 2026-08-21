//! Build and verify one self-describing production-v2 artifact directory.
//!
//! `vos-service.pvm` is the consensus program all hosts execute. The frozen
//! `space-authority.pvm` is the durable Batch-70 authority identity already
//! sealed into production spaces. A release must carry these exact pins
//! together; selecting either artifact from a developer build directory would
//! make a deployment unreproducible or an existing space impossible to open.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use vos::v2::{ProgramId, ServicePvmV2};

use crate::bundled;

const RELEASE_FORMAT: &str = "VOSR1";
const RELEASE_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const SERVICE_FILE: &str = "vos-service.pvm";
const AUTHORITY_FILE: &str = "space-authority.pvm";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub enum ReleaseCommand {
    /// Create a new directory containing both pinned PVMs and their manifest.
    Bundle {
        /// Committed/freshly reproduced canonical `vos-service.pvm`.
        #[arg(long)]
        service_pvm: PathBuf,
        /// New output directory. Existing paths are never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a release directory against this binary's protocol pins.
    Verify {
        /// Directory created by `vosx release bundle`.
        directory: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    format: String,
    version: u32,
    platform_abi: u16,
    store_schema: u16,
    execution_semantics: String,
    service: ReleaseArtifact,
    authority: ReleaseArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseArtifact {
    file: String,
    bytes: u64,
    blake2b_256: String,
    program_id: String,
}

pub fn run(command: ReleaseCommand) -> anyhow::Result<()> {
    match command {
        ReleaseCommand::Bundle { service_pvm, out } => bundle(&service_pvm, &out),
        ReleaseCommand::Verify { directory } => verify(&directory).map(|manifest| {
            println!(
                "verified {} (ABI {}, schema {}, semantics {})",
                directory.display(),
                manifest.platform_abi,
                manifest.store_schema,
                manifest.execution_semantics,
            );
        }),
    }
}

fn bundle(service_path: &Path, output: &Path) -> anyhow::Result<()> {
    if path_exists(output)? {
        bail!(
            "release output {} already exists; choose a new directory",
            output.display(),
        );
    }
    let service = read_regular_bounded(service_path, MAX_ARTIFACT_BYTES)?;
    validate_service(&service)?;
    let authority = bundled::space_authority_pvm()
        .context("this vosx build does not contain the frozen production authority")?;
    validate_authority(authority)?;
    let manifest = manifest_for(&service, authority);

    let parent = nonempty_parent(output);
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // `create_dir` is the no-clobber activation point. Building in a sibling
    // and calling ordinary `rename` would have a TOCTOU window in which an
    // empty destination created by another operator could be replaced.
    fs::create_dir(output).with_context(|| format!("reserve {}", output.display()))?;
    let mut guard = PartialDirectory(Some(output.to_path_buf()));
    fs::write(output.join(SERVICE_FILE), &service).context("write pinned service PVM")?;
    fs::write(output.join(AUTHORITY_FILE), authority).context("write frozen authority PVM")?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).context("encode release manifest")?;
    fs::write(output.join(MANIFEST_FILE), manifest_bytes).context("write release manifest")?;
    verify(output).context("verify staged production release")?;
    guard.0 = None;
    println!("bundled production v2 artifacts at {}", output.display());
    println!("  service_program_id = {}", manifest.service.program_id);
    println!("  authority_program_id = {}", manifest.authority.program_id);
    Ok(())
}

fn verify(directory: &Path) -> anyhow::Result<ReleaseManifest> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("inspect release directory {}", directory.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("release path must be a real directory, not a symlink");
    }
    let expected_names = BTreeSet::from([
        MANIFEST_FILE.to_owned(),
        SERVICE_FILE.to_owned(),
        AUTHORITY_FILE.to_owned(),
    ]);
    let mut actual_names = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read release directory {}", directory.display()))?
    {
        let entry = entry.context("read release directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("release contains a non-UTF-8 file name"))?;
        actual_names.insert(name);
    }
    if actual_names != expected_names {
        bail!(
            "release directory must contain exactly {MANIFEST_FILE}, {SERVICE_FILE}, and {AUTHORITY_FILE}",
        );
    }

    let manifest_bytes = read_regular_bounded(&directory.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).context("decode production release manifest")?;
    let service = read_regular_bounded(&directory.join(SERVICE_FILE), MAX_ARTIFACT_BYTES)?;
    let authority = read_regular_bounded(&directory.join(AUTHORITY_FILE), MAX_ARTIFACT_BYTES)?;
    validate_service(&service)?;
    validate_authority(&authority)?;
    let expected = manifest_for(&service, &authority);
    if manifest != expected {
        bail!("release manifest does not describe the exact pinned artifacts");
    }
    Ok(manifest)
}

fn validate_service(bytes: &[u8]) -> anyhow::Result<()> {
    let actual = ProgramId::of_pvm(bytes);
    if actual != vos::v2::VOS_SERVICE_PROGRAM_ID {
        bail!(
            "service PVM has program {}, expected protocol pin {}",
            hex::encode(actual.0),
            hex::encode(vos::v2::VOS_SERVICE_PROGRAM_ID.0),
        );
    }
    ServicePvmV2::new(bytes.to_vec(), actual)
        .map_err(|error| anyhow::anyhow!("invalid canonical service PVM: {error}"))?;
    Ok(())
}

fn validate_authority(bytes: &[u8]) -> anyhow::Result<()> {
    let digest = vos::crypto::blake2b_hash::<32>(&[], &[bytes]);
    if digest != bundled::SPACE_AUTHORITY_BLAKE2B_256 {
        bail!("authority PVM does not match the frozen Batch-70 release bytes");
    }
    let program = ProgramId::of_pvm(bytes);
    if program.0 != bundled::SPACE_AUTHORITY_PROGRAM_ID {
        bail!("authority PVM does not match the frozen Batch-70 program identity");
    }
    Ok(())
}

fn manifest_for(service: &[u8], authority: &[u8]) -> ReleaseManifest {
    ReleaseManifest {
        format: RELEASE_FORMAT.into(),
        version: RELEASE_VERSION,
        platform_abi: vos::v2::ABI_VERSION,
        store_schema: vos::v2::SERVICE_STORE_SCHEMA_VERSION,
        execution_semantics: hex::encode(vos::v2::EXECUTION_SEMANTICS_ID.0),
        service: artifact(SERVICE_FILE, service),
        authority: artifact(AUTHORITY_FILE, authority),
    }
}

fn artifact(file: &str, bytes: &[u8]) -> ReleaseArtifact {
    ReleaseArtifact {
        file: file.into(),
        bytes: bytes.len() as u64,
        blake2b_256: hex::encode(vos::crypto::blake2b_hash::<32>(&[], &[bytes])),
        program_id: hex::encode(ProgramId::of_pvm(bytes).0),
    }
}

fn read_regular_bounded(path: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open regular file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect open file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{} must be a regular file, not a symlink", path.display());
    }
    if metadata.len() == 0 || metadata.len() > max {
        bail!(
            "{} has invalid size {} (expected 1..={max})",
            path.display(),
            metadata.len(),
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(max) as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > max {
        bail!("{} grew beyond the {max}-byte limit", path.display());
    }
    Ok(bytes)
}

fn path_exists(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn nonempty_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct PartialDirectory(Option<PathBuf>);

impl Drop for PartialDirectory {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_binds_protocol_versions_and_both_artifacts() {
        let manifest = manifest_for(b"service", b"authority");
        assert_eq!(manifest.format, "VOSR1");
        assert_eq!(manifest.platform_abi, vos::v2::ABI_VERSION);
        assert_eq!(manifest.store_schema, vos::v2::SERVICE_STORE_SCHEMA_VERSION);
        assert_eq!(manifest.service.file, SERVICE_FILE);
        assert_eq!(manifest.authority.file, AUTHORITY_FILE);
        assert_ne!(manifest.service.blake2b_256, manifest.authority.blake2b_256);
    }

    #[test]
    fn authority_pin_rejects_changed_bytes() {
        assert!(validate_authority(b"not the frozen authority").is_err());
    }
}
