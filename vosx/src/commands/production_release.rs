//! Build and verify one self-describing production artifact directory.
//!
//! `vos-service.pvm` is the consensus program all hosts execute. The canonical
//! `space-authority.pvm` is the authority identity sealed into new production
//! spaces. `agent-runtime.pvm` is the standard runtime installed for agents
//! that do not select a compatible custom runtime. A release must carry these
//! exact pins together; selecting an artifact from a developer build directory
//! would make a deployment unreproducible or an existing space impossible to
//! open.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use vos::service::{ProgramId, ServicePvm};

use crate::bundled;

const RELEASE_FORMAT: &str = "VOS-RELEASE";
const MANIFEST_FILE: &str = "manifest.json";
const SERVICE_FILE: &str = "vos-service.pvm";
const AUTHORITY_FILE: &str = "space-authority.pvm";
const AGENT_RUNTIME_FILE: &str = "agent-runtime.pvm";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub enum ReleaseCommand {
    /// Create a new directory containing the pinned PVMs and their manifest.
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
    platform: String,
    service_execution_semantics: String,
    agent_execution_semantics: String,
    service: ReleaseArtifact,
    authority: ReleaseArtifact,
    agent_runtime: ReleaseArtifact,
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
                "verified {} (platform {}, service semantics {}, agent semantics {})",
                directory.display(),
                manifest.platform,
                manifest.service_execution_semantics,
                manifest.agent_execution_semantics,
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
    let agent_runtime = bundled::agent_runtime_pvm();
    validate_agent_runtime(agent_runtime)?;
    let manifest = manifest_for(&service, authority, agent_runtime);

    let parent = nonempty_parent(output);
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // `create_dir` is the no-clobber activation point. Building in a sibling
    // and calling ordinary `rename` would have a TOCTOU window in which an
    // empty destination created by another operator could be replaced.
    fs::create_dir(output).with_context(|| format!("reserve {}", output.display()))?;
    let mut guard = PartialDirectory(Some(output.to_path_buf()));
    fs::write(output.join(SERVICE_FILE), &service).context("write pinned service PVM")?;
    fs::write(output.join(AUTHORITY_FILE), authority).context("write canonical authority PVM")?;
    fs::write(output.join(AGENT_RUNTIME_FILE), agent_runtime)
        .context("write canonical agent runtime PVM")?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).context("encode release manifest")?;
    fs::write(output.join(MANIFEST_FILE), manifest_bytes).context("write release manifest")?;
    verify(output).context("verify staged production release")?;
    guard.0 = None;
    println!("bundled production artifacts at {}", output.display());
    println!("  service_program_id = {}", manifest.service.program_id);
    println!("  authority_program_id = {}", manifest.authority.program_id);
    println!(
        "  agent_runtime_program_id = {}",
        manifest.agent_runtime.program_id
    );
    Ok(())
}

fn verify(directory: &Path) -> anyhow::Result<ReleaseManifest> {
    // `symlink_metadata("release-link/")` follows the final directory
    // symlink on Unix. Rebuild the lexical path first so the final separator
    // cannot change which object is inspected, and use that path for every
    // subsequent operation.
    let directory = normalize_release_directory(directory)?;
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspect release directory {}", directory.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("release path must be a real directory, not a symlink");
    }
    verify_directory_shape(&directory)?;

    let manifest_bytes = read_regular_bounded(&directory.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).context("decode production release manifest")?;
    let service = read_regular_bounded(&directory.join(SERVICE_FILE), MAX_ARTIFACT_BYTES)?;
    let authority = read_regular_bounded(&directory.join(AUTHORITY_FILE), MAX_ARTIFACT_BYTES)?;
    let agent_runtime =
        read_regular_bounded(&directory.join(AGENT_RUNTIME_FILE), MAX_ARTIFACT_BYTES)?;
    validate_service(&service)?;
    validate_authority(&authority)?;
    validate_agent_runtime(&agent_runtime)?;
    validate_manifest(&manifest, &service, &authority, &agent_runtime)?;
    Ok(manifest)
}

fn validate_manifest(
    manifest: &ReleaseManifest,
    service: &[u8],
    authority: &[u8],
    agent_runtime: &[u8],
) -> anyhow::Result<()> {
    let expected = manifest_for(service, authority, agent_runtime);
    if manifest != &expected {
        bail!("release manifest does not describe the exact pinned artifacts");
    }
    Ok(())
}

fn validate_service(bytes: &[u8]) -> anyhow::Result<()> {
    let actual = ProgramId::of_pvm(bytes);
    if actual != vos::service::VOS_SERVICE_PROGRAM_ID {
        bail!(
            "service PVM has program {}, expected protocol pin {}",
            hex::encode(actual.0),
            hex::encode(vos::service::VOS_SERVICE_PROGRAM_ID.0),
        );
    }
    ServicePvm::new(bytes.to_vec(), actual)
        .map_err(|error| anyhow::anyhow!("invalid canonical service PVM: {error}"))?;
    Ok(())
}

fn validate_authority(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::space_authority_pvm()
        .context("this vosx build does not contain the frozen production authority")?;
    if bytes != canonical {
        bail!("authority PVM does not match the canonical release bytes");
    }
    Ok(())
}

fn validate_agent_runtime(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::agent_runtime_pvm();
    if bytes != canonical {
        bail!("agent runtime PVM does not match the canonical release bytes");
    }
    let actual = ProgramId::of_pvm(bytes);
    if actual != vos::agent::STANDARD_RUNTIME_PROGRAM_ID {
        bail!(
            "agent runtime PVM has program {}, expected protocol pin {}",
            hex::encode(actual.0),
            hex::encode(vos::agent::STANDARD_RUNTIME_PROGRAM_ID.0),
        );
    }
    Ok(())
}

fn manifest_for(service: &[u8], authority: &[u8], agent_runtime: &[u8]) -> ReleaseManifest {
    ReleaseManifest {
        format: RELEASE_FORMAT.into(),
        platform: hex::encode(vos::service::PLATFORM_ID.0),
        service_execution_semantics: hex::encode(vos::service::EXECUTION_SEMANTICS_ID.0),
        agent_execution_semantics: hex::encode(vos::agent::EXECUTION_SEMANTICS_ID.0),
        service: artifact(SERVICE_FILE, service),
        authority: artifact(AUTHORITY_FILE, authority),
        agent_runtime: artifact(AGENT_RUNTIME_FILE, agent_runtime),
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
        // The type check must happen on the opened object to avoid a
        // check/open race. O_NONBLOCK makes opening an expected-name FIFO
        // return immediately so fstat can reject it instead of hanging the
        // release verifier.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect regular file {}", path.display()))?;
        if !metadata.file_type().is_file() {
            bail!("{} must be a regular file", path.display());
        }
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

fn normalize_release_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                bail!("release directory path must not contain `..`");
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Ok(normalized)
}

fn verify_directory_shape(directory: &Path) -> anyhow::Result<()> {
    let mut seen = [false; 4];
    let mut count = 0usize;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read release directory {}", directory.display()))?
    {
        let entry = entry.context("read release directory entry")?;
        count += 1;
        if count > seen.len() {
            bail!(
                "release directory must contain exactly {MANIFEST_FILE}, {SERVICE_FILE}, {AUTHORITY_FILE}, and {AGENT_RUNTIME_FILE}",
            );
        }
        let name = entry.file_name();
        let index = match name.to_str() {
            Some(MANIFEST_FILE) => 0,
            Some(SERVICE_FILE) => 1,
            Some(AUTHORITY_FILE) => 2,
            Some(AGENT_RUNTIME_FILE) => 3,
            Some(_) => bail!("release directory contains an unexpected entry"),
            None => bail!("release contains a non-UTF-8 file name"),
        };
        if std::mem::replace(&mut seen[index], true) {
            bail!("release directory contains a duplicate entry");
        }
    }
    if count != seen.len() || !seen.into_iter().all(|present| present) {
        bail!(
            "release directory must contain exactly {MANIFEST_FILE}, {SERVICE_FILE}, {AUTHORITY_FILE}, and {AGENT_RUNTIME_FILE}",
        );
    }
    Ok(())
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

    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vosx-release-{label}-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&path).expect("create release test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn manifest_binds_platform_and_all_artifacts() {
        let manifest = manifest_for(b"service", b"authority", b"agent runtime");
        assert_eq!(manifest.format, RELEASE_FORMAT);
        assert_eq!(manifest.platform, hex::encode(vos::service::PLATFORM_ID.0));
        assert_eq!(
            manifest.service_execution_semantics,
            hex::encode(vos::service::EXECUTION_SEMANTICS_ID.0),
        );
        assert_eq!(
            manifest.agent_execution_semantics,
            hex::encode(vos::agent::EXECUTION_SEMANTICS_ID.0),
        );
        assert_ne!(
            manifest.service_execution_semantics,
            manifest.agent_execution_semantics,
        );
        assert_eq!(manifest.service.file, SERVICE_FILE);
        assert_eq!(manifest.authority.file, AUTHORITY_FILE);
        assert_eq!(manifest.agent_runtime.file, AGENT_RUNTIME_FILE);
        assert_ne!(manifest.service.blake2b_256, manifest.authority.blake2b_256);
        assert_ne!(
            manifest.authority.blake2b_256,
            manifest.agent_runtime.blake2b_256
        );
    }

    #[test]
    fn release_manifest_has_no_single_semantics_fallback() {
        let manifest = manifest_for(b"service", b"authority", b"agent runtime");
        let mut value = serde_json::to_value(manifest)
            .expect("serialize manifest")
            .as_object()
            .expect("manifest object")
            .clone();
        value.remove("service_execution_semantics");
        value.remove("agent_execution_semantics");
        value.insert(
            "execution_semantics".into(),
            serde_json::Value::String(hex::encode(vos::service::EXECUTION_SEMANTICS_ID.0)),
        );
        assert!(
            serde_json::from_value::<ReleaseManifest>(serde_json::Value::Object(value)).is_err(),
            "the former one-profile release schema must not be accepted",
        );
    }

    #[test]
    fn release_manifest_rejects_the_previous_agent_semantics() {
        let mut manifest = manifest_for(b"service", b"authority", b"agent runtime");
        manifest.agent_execution_semantics = hex::encode(*b"vos-pvm-41d31e6-standard-gas-r02");
        assert!(
            validate_manifest(&manifest, b"service", b"authority", b"agent runtime").is_err(),
            "a release produced for the immediately previous Agent semantics must fail closed",
        );
    }

    #[test]
    fn authority_pin_rejects_changed_bytes() {
        assert!(validate_authority(b"not the canonical authority").is_err());
    }

    #[test]
    fn bundled_authority_matches_the_runtime_release_pins() {
        let authority = bundled::space_authority_pvm().expect("bundled authority");
        validate_authority(authority).expect("build-time and runtime authority pins must agree");
    }

    #[test]
    fn agent_runtime_pin_rejects_changed_bytes() {
        assert!(validate_agent_runtime(b"not the canonical agent runtime").is_err());
    }

    #[test]
    fn bundled_agent_runtime_matches_the_protocol_release_pin() {
        let runtime = bundled::agent_runtime_pvm();
        validate_agent_runtime(runtime)
            .expect("build-time and protocol agent-runtime pins must agree");
        assert_eq!(
            ProgramId::of_pvm(runtime),
            vos::agent::STANDARD_RUNTIME_PROGRAM_ID
        );
    }

    #[cfg(unix)]
    #[test]
    fn expected_name_fifo_is_rejected_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let temp = TestDir::new("fifo");
        let fifo = temp.0.join(MANIFEST_FILE);
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
        // SAFETY: `fifo_c` is a live, NUL-terminated path and the mode has no
        // platform-dependent pointers or ownership requirements.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(read_regular_bounded(&fifo, MAX_MANIFEST_BYTES).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "special-file rejection must not wait for a writer",
        );
    }

    #[test]
    fn directory_scan_rejects_the_first_surplus_entry() {
        let temp = TestDir::new("surplus");
        for name in [
            MANIFEST_FILE,
            SERVICE_FILE,
            AUTHORITY_FILE,
            AGENT_RUNTIME_FILE,
            "surplus",
        ] {
            fs::write(temp.0.join(name), b"x").expect("write test entry");
        }
        assert!(verify_directory_shape(&temp.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trailing_separator_does_not_hide_a_directory_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("directory-symlink");
        let target = temp.0.join("target");
        fs::create_dir(&target).expect("create symlink target");
        let link = temp.0.join("release-link");
        symlink(&target, &link).expect("create directory symlink");
        let trailing = PathBuf::from(format!("{}/", link.display()));
        let error = verify(&trailing).expect_err("directory symlink must be rejected");
        assert!(error.to_string().contains("real directory"));
    }
}
