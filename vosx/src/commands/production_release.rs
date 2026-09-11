//! Build and verify one self-describing Agent-generation release directory.
//!
//! The released `vosx` binary already embeds every program needed to create a
//! fresh space: the standard AgentRuntime and the authority and catalog system
//! actors. `release bundle` materializes those exact checked pins without any
//! caller-supplied program path. That keeps the release identity reproducible
//! and prevents a retired root-service program from being smuggled back into
//! an otherwise current bundle.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use vos::agent::sdk::ProgramId as AgentProgramId;

use crate::bundled;

const RELEASE_FORMAT: &str = "VOS-AGENT-RELEASE-1";
const MANIFEST_FILE: &str = "manifest.json";
const STANDARD_RUNTIME_FILE: &str = "standard-runtime.pvm";
const AUTHORITY_FILE: &str = "system-authority.pvm";
const CATALOG_FILE: &str = "system-catalog.pvm";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub enum ReleaseCommand {
    /// Build reproducible system-package templates, never operator credentials.
    BuildSystemTemplates {
        /// Exact source checkout/export containing actors/system-{authority,catalog}.
        #[arg(long)]
        source: PathBuf,
        /// Fresh candidate output directory; existing paths are rejected.
        #[arg(long)]
        out: PathBuf,
    },
    /// Materialize the programs pinned inside this binary and their manifest.
    Bundle {
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
    agent_execution_semantics: String,
    standard_runtime: ReleaseArtifact,
    authority_actor: ReleaseArtifact,
    catalog_actor: ReleaseArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseArtifact {
    kind: ReleaseArtifactKind,
    file: String,
    bytes: u64,
    blake2b_256: String,
    program_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseArtifactKind {
    AgentRuntime,
    Actor,
}

pub fn run(command: ReleaseCommand) -> anyhow::Result<()> {
    match command {
        ReleaseCommand::BuildSystemTemplates { source, out } => {
            build_system_templates(&source, &out)
        }
        ReleaseCommand::Bundle { out } => bundle(&out),
        ReleaseCommand::Verify { directory } => verify(&directory).map(|manifest| {
            println!(
                "verified {} (Agent execution semantics {})",
                directory.display(),
                manifest.agent_execution_semantics,
            );
        }),
    }
}

fn system_template_signer() -> anyhow::Result<libp2p::identity::Keypair> {
    // PUBLIC, NON-AUTHORITATIVE reproducibility seed. These envelopes are
    // pinned by source and digest, not trusted because of this signature.
    // Space creation re-signs them with the actual root. Never persist this
    // key as an operator identity or use it to authorize a space operation.
    libp2p::identity::Keypair::ed25519_from_bytes([0x54; 32])
        .context("construct public system-template signer")
}

fn build_system_templates(source: &Path, out: &Path) -> anyhow::Result<()> {
    let source = fs::canonicalize(source).context("resolve system-template source")?;
    for name in ["system-authority", "system-catalog"] {
        if !source
            .join("actors")
            .join(name)
            .join("Cargo.toml")
            .is_file()
        {
            bail!("system-template source is missing actor {name}");
        }
    }
    if path_exists(out)? {
        bail!(
            "template output {} already exists; choose a new directory",
            out.display()
        );
    }
    fs::create_dir_all(nonempty_parent(out))?;
    fs::create_dir(out).context("create fresh system-template output")?;
    let signer = system_template_signer()?;
    for name in ["system-authority", "system-catalog"] {
        super::build::run_with_signer(
            super::build::Args {
                program: source.join("actors").join(name),
                name: Some(name.into()),
                out_dir: out.to_path_buf(),
                method_policy: None,
                schemas: None,
                agent_schema: None,
                agent_authorizations: None,
                tasks: Vec::new(),
                crdt: false,
                scheduling: false,
                proof_system: None,
            },
            &signer,
        )?;
    }
    Ok(())
}

fn bundle(output: &Path) -> anyhow::Result<()> {
    if path_exists(output)? {
        bail!(
            "release output {} already exists; choose a new directory",
            output.display(),
        );
    }
    let standard_runtime = bundled::agent_runtime_pvm();
    validate_standard_runtime(standard_runtime)?;
    let authority = bundled::space_authority_pvm()
        .context("this vosx build does not contain the frozen production authority")?;
    validate_authority(authority)?;
    let catalog = canonical_catalog_pvm()?;
    validate_catalog(&catalog)?;
    let manifest = manifest_for(standard_runtime, authority, &catalog);

    let parent = nonempty_parent(output);
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // `create_dir` is the no-clobber activation point. Building in a sibling
    // and calling ordinary `rename` would have a TOCTOU window in which an
    // empty destination created by another operator could be replaced.
    fs::create_dir(output).with_context(|| format!("reserve {}", output.display()))?;
    let mut guard = PartialDirectory(Some(output.to_path_buf()));
    fs::write(output.join(STANDARD_RUNTIME_FILE), standard_runtime)
        .context("write canonical standard runtime")?;
    fs::write(output.join(AUTHORITY_FILE), authority)
        .context("write canonical system-authority actor")?;
    fs::write(output.join(CATALOG_FILE), &catalog)
        .context("write canonical system-catalog actor")?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).context("encode release manifest")?;
    fs::write(output.join(MANIFEST_FILE), manifest_bytes).context("write release manifest")?;
    verify(output).context("verify staged production release")?;
    guard.0 = None;
    println!("bundled production artifacts at {}", output.display());
    println!(
        "  standard_runtime_program_id = {}",
        manifest.standard_runtime.program_id
    );
    println!(
        "  authority_actor_program_id = {}",
        manifest.authority_actor.program_id
    );
    println!(
        "  catalog_actor_program_id = {}",
        manifest.catalog_actor.program_id
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
    let standard_runtime =
        read_regular_bounded(&directory.join(STANDARD_RUNTIME_FILE), MAX_ARTIFACT_BYTES)?;
    let authority = read_regular_bounded(&directory.join(AUTHORITY_FILE), MAX_ARTIFACT_BYTES)?;
    let catalog = read_regular_bounded(&directory.join(CATALOG_FILE), MAX_ARTIFACT_BYTES)?;
    validate_standard_runtime(&standard_runtime)?;
    validate_authority(&authority)?;
    validate_catalog(&catalog)?;
    validate_manifest(&manifest, &standard_runtime, &authority, &catalog)?;
    Ok(manifest)
}

fn validate_manifest(
    manifest: &ReleaseManifest,
    standard_runtime: &[u8],
    authority: &[u8],
    catalog: &[u8],
) -> anyhow::Result<()> {
    let expected = manifest_for(standard_runtime, authority, catalog);
    if manifest != &expected {
        bail!("release manifest does not describe the exact pinned artifacts");
    }
    Ok(())
}

fn validate_authority(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::space_authority_pvm()
        .context("this vosx build does not contain the frozen production authority")?;
    if bytes != canonical {
        bail!("authority PVM does not match the canonical release bytes");
    }
    validate_actor_program(bytes, "system-authority actor")?;
    Ok(())
}

fn validate_standard_runtime(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::agent_runtime_pvm();
    if bytes != canonical {
        bail!("standard runtime does not match the canonical release bytes");
    }
    validate_standard_runtime_program(bytes)?;
    let actual = AgentProgramId::of_pvm(bytes);
    let expected = AgentProgramId(vos::agent::STANDARD_RUNTIME_PROGRAM_ID.0);
    if actual != expected {
        bail!(
            "standard runtime has program {}, expected protocol pin {}",
            hex::encode(actual.0),
            hex::encode(expected.0),
        );
    }
    Ok(())
}

fn canonical_catalog_pvm() -> anyhow::Result<Vec<u8>> {
    let elf = bundled::registry_elf()
        .context("this vosx build does not contain the frozen production catalog")?;
    vos_pvm_compiler::link_elf(elf)
        .map_err(|error| anyhow::anyhow!("link canonical system-catalog actor: {error:?}"))
}

fn validate_catalog(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = canonical_catalog_pvm()?;
    if bytes != canonical {
        bail!("catalog PVM does not match the canonical release bytes");
    }
    validate_actor_program(bytes, "system-catalog actor")
}

fn validate_standard_runtime_program(bytes: &[u8]) -> anyhow::Result<()> {
    vos_pvm::spi::validate_refine_host_calls(bytes).map_err(|error| {
        anyhow::anyhow!("AgentRuntime outer host-call surface is invalid: {error:?}")
    })
}

fn validate_actor_program(bytes: &[u8], label: &str) -> anyhow::Result<()> {
    vos_pvm::program::parse_blob(bytes)
        .ok_or_else(|| anyhow::anyhow!("{label} is not a canonical actor PVM program"))?;
    Ok(())
}

fn manifest_for(standard_runtime: &[u8], authority: &[u8], catalog: &[u8]) -> ReleaseManifest {
    ReleaseManifest {
        format: RELEASE_FORMAT.into(),
        agent_execution_semantics: hex::encode(vos::agent::EXECUTION_SEMANTICS_ID.0),
        standard_runtime: artifact(
            ReleaseArtifactKind::AgentRuntime,
            STANDARD_RUNTIME_FILE,
            standard_runtime,
        ),
        authority_actor: artifact(ReleaseArtifactKind::Actor, AUTHORITY_FILE, authority),
        catalog_actor: artifact(ReleaseArtifactKind::Actor, CATALOG_FILE, catalog),
    }
}

fn artifact(kind: ReleaseArtifactKind, file: &str, bytes: &[u8]) -> ReleaseArtifact {
    ReleaseArtifact {
        kind,
        file: file.into(),
        bytes: bytes.len() as u64,
        blake2b_256: hex::encode(vos::crypto::blake2b_hash::<32>(&[], &[bytes])),
        program_id: hex::encode(AgentProgramId::of_pvm(bytes).0),
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
                "release directory must contain exactly {MANIFEST_FILE}, {STANDARD_RUNTIME_FILE}, {AUTHORITY_FILE}, and {CATALOG_FILE}",
            );
        }
        let name = entry.file_name();
        let index = match name.to_str() {
            Some(MANIFEST_FILE) => 0,
            Some(STANDARD_RUNTIME_FILE) => 1,
            Some(AUTHORITY_FILE) => 2,
            Some(CATALOG_FILE) => 3,
            Some(_) => bail!("release directory contains an unexpected entry"),
            None => bail!("release contains a non-UTF-8 file name"),
        };
        if std::mem::replace(&mut seen[index], true) {
            bail!("release directory contains a duplicate entry");
        }
    }
    if count != seen.len() || !seen.into_iter().all(|present| present) {
        bail!(
            "release directory must contain exactly {MANIFEST_FILE}, {STANDARD_RUNTIME_FILE}, {AUTHORITY_FILE}, and {CATALOG_FILE}",
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
    fn system_template_signing_is_public_and_deterministic() {
        let first = system_template_signer().unwrap();
        let second = system_template_signer().unwrap();
        assert_eq!(first.public(), second.public());
        let message = b"non-authoritative system-template fixture";
        assert_eq!(first.sign(message).unwrap(), second.sign(message).unwrap());
        assert!(
            first
                .public()
                .verify(message, &first.sign(message).unwrap())
        );
    }

    #[test]
    fn system_templates_reject_existing_output_without_modifying_it() {
        let out = TestDir::new("templates-existing");
        let sentinel = out.0.join("keep");
        fs::write(&sentinel, b"unchanged").unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert!(build_system_templates(source, &out.0).is_err());
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
    }

    #[test]
    fn system_templates_validate_source_before_creating_output() {
        let source = TestDir::new("templates-missing-source");
        let out = source.0.join("output");
        assert!(build_system_templates(&source.0, &out).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn manifest_binds_execution_semantics_kinds_and_all_artifacts() {
        let manifest = manifest_for(b"standard runtime", b"authority", b"catalog");
        assert_eq!(manifest.format, RELEASE_FORMAT);
        assert_eq!(
            manifest.agent_execution_semantics,
            hex::encode(vos::agent::EXECUTION_SEMANTICS_ID.0),
        );
        assert_eq!(manifest.standard_runtime.file, STANDARD_RUNTIME_FILE);
        assert_eq!(
            manifest.standard_runtime.kind,
            ReleaseArtifactKind::AgentRuntime
        );
        assert_eq!(manifest.authority_actor.file, AUTHORITY_FILE);
        assert_eq!(manifest.authority_actor.kind, ReleaseArtifactKind::Actor);
        assert_eq!(manifest.catalog_actor.file, CATALOG_FILE);
        assert_eq!(manifest.catalog_actor.kind, ReleaseArtifactKind::Actor);
        assert_ne!(
            manifest.standard_runtime.blake2b_256,
            manifest.authority_actor.blake2b_256
        );
        assert_ne!(
            manifest.authority_actor.blake2b_256,
            manifest.catalog_actor.blake2b_256
        );
    }

    #[test]
    fn release_manifest_rejects_retired_root_service_shape() {
        let manifest = manifest_for(b"standard runtime", b"authority", b"catalog");
        let mut value = serde_json::to_value(manifest)
            .expect("serialize manifest")
            .as_object()
            .expect("manifest object")
            .clone();
        value.insert(
            "service".into(),
            serde_json::json!({
                "file": "vos-service.pvm",
                "bytes": 1,
                "blake2b_256": "00",
                "program_id": "00"
            }),
        );
        assert!(
            serde_json::from_value::<ReleaseManifest>(serde_json::Value::Object(value)).is_err(),
            "the retired root-service release schema must not be accepted",
        );
    }

    #[test]
    fn release_manifest_rejects_the_previous_agent_semantics() {
        let mut manifest = manifest_for(b"standard runtime", b"authority", b"catalog");
        manifest.agent_execution_semantics = hex::encode(*b"vos-pvm-41d31e6-standard-gas-r02");
        assert!(
            validate_manifest(&manifest, b"standard runtime", b"authority", b"catalog").is_err(),
            "a release produced for the immediately previous Agent semantics must fail closed",
        );
    }

    #[test]
    fn release_manifest_uses_one_program_identity_domain() {
        let runtime = b"agent runtime";
        let authority = b"authority actor";
        let catalog = b"catalog actor";
        let manifest = manifest_for(runtime, authority, catalog);
        assert_eq!(
            manifest.standard_runtime.program_id,
            hex::encode(AgentProgramId::of_pvm(runtime).0),
        );
        assert_eq!(
            manifest.authority_actor.program_id,
            hex::encode(AgentProgramId::of_pvm(authority).0),
        );
        assert_eq!(
            manifest.catalog_actor.program_id,
            hex::encode(AgentProgramId::of_pvm(catalog).0),
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
    fn standard_runtime_pin_rejects_changed_bytes() {
        assert!(validate_standard_runtime(b"not the canonical agent runtime").is_err());
    }

    #[test]
    fn standard_runtime_program_rejects_vos_only_outer_host_calls() {
        use vos_pvm_compiler::assembler::Assembler;

        let mut program = Assembler::new();
        let program = program
            .ecalli(vos::abi::hostcall::DEBUG_WRITE)
            .trap()
            .build_standard();
        let error = validate_standard_runtime_program(&program)
            .expect_err("release verification must inspect the complete outer host-call surface");
        assert!(
            error.to_string().contains("UnsupportedHostCall(118)"),
            "unexpected rejection: {error:#}"
        );
    }

    #[test]
    fn bundled_standard_runtime_matches_the_protocol_release_pin() {
        let runtime = bundled::agent_runtime_pvm();
        validate_standard_runtime(runtime)
            .expect("build-time and protocol agent-runtime pins must agree");
        assert_eq!(
            AgentProgramId::of_pvm(runtime),
            AgentProgramId(vos::agent::STANDARD_RUNTIME_PROGRAM_ID.0),
        );
    }

    #[test]
    fn bundled_catalog_links_to_the_exact_release_pin() {
        let catalog = canonical_catalog_pvm().expect("link bundled catalog");
        validate_catalog(&catalog).expect("linked and release catalog pins must agree");
    }

    #[test]
    fn bundle_is_self_contained_and_byte_reproducible() {
        let temp = TestDir::new("reproducible");
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        bundle(&first).expect("first bundle");
        bundle(&second).expect("second bundle");
        let first_manifest = verify(&first).expect("verify first bundle");
        let second_manifest = verify(&second).expect("verify second bundle");
        assert_eq!(first_manifest, second_manifest);
        for file in [
            MANIFEST_FILE,
            STANDARD_RUNTIME_FILE,
            AUTHORITY_FILE,
            CATALOG_FILE,
        ] {
            assert_eq!(
                fs::read(first.join(file)).expect("read first artifact"),
                fs::read(second.join(file)).expect("read second artifact"),
                "artifact={file}",
            );
        }
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
            STANDARD_RUNTIME_FILE,
            AUTHORITY_FILE,
            CATALOG_FILE,
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
