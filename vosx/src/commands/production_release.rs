//! Build and verify one self-describing Agent-generation release directory.
//!
//! The released `vosx` binary already embeds every program needed to create a
//! fresh space: the unchanged Local AgentRuntime, separate System observation
//! and external Shared runtime templates, and authority/catalog system actors.
//! `release bundle` materializes those exact checked pins without any
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

const RELEASE_FORMAT: &str = "VOS-AGENT-RELEASE-2";
const MANIFEST_FILE: &str = "manifest.json";
const STANDARD_RUNTIME_FILE: &str = "standard-runtime.pvm";
const AUTHORITY_FILE: &str = "system-authority.vos";
const CATALOG_FILE: &str = "system-catalog.vos";
const SYSTEM_IMAGE_RUNTIME_FILE: &str = "system-image-runtime.vos";
const SHARED_EXTERNAL_RUNTIME_FILE: &str = "shared-external-runtime.vos";
#[cfg(any(feature = "experimental-state-blocks", test))]
const MAX_EXTERNAL_LIMITS_BYTES: u64 = 8 * 1024;
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
        /// Build an experimental Authority candidate; never replaces release pins.
        #[arg(long)]
        experimental_state_blocks: bool,
        /// Source-coherent System IMAGE PVM; supply all three runtime-role inputs.
        /// This never replaces the existing Local standard-runtime pin.
        #[arg(long, requires_all = ["shared_runtime_pvm", "external_state_limits", "experimental_state_blocks"])]
        system_runtime_pvm: Option<PathBuf>,
        /// Source-coherent Shared EXTERNAL PVM, explicitly selected with --runtime.
        #[arg(long, requires_all = ["system_runtime_pvm", "external_state_limits", "experimental_state_blocks"])]
        shared_runtime_pvm: Option<PathBuf>,
        /// Explicit JSON object with max_rows_per_lane and max_row_bytes_per_lane.
        /// No default or qualification claim is inferred from ABI-probe limits.
        #[arg(long, requires_all = ["system_runtime_pvm", "shared_runtime_pvm", "experimental_state_blocks"])]
        external_state_limits: Option<PathBuf>,
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
    system_image_runtime: ReleaseArtifact,
    shared_external_runtime: ReleaseArtifact,
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
    AgentRuntimePackageTemplate,
    ActorPackageTemplate,
}

pub fn run(command: ReleaseCommand) -> anyhow::Result<()> {
    match command {
        ReleaseCommand::BuildSystemTemplates {
            source,
            out,
            experimental_state_blocks,
            system_runtime_pvm,
            shared_runtime_pvm,
            external_state_limits,
        } => {
            let roles = runtime_role_inputs(
                system_runtime_pvm.as_deref(),
                shared_runtime_pvm.as_deref(),
                external_state_limits.as_deref(),
            )?;
            build_system_templates(&source, &out, experimental_state_blocks, roles)
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

fn build_system_templates(
    source: &Path,
    out: &Path,
    experimental_state_blocks: bool,
    runtime_roles: Option<RuntimeRoleTemplateInputs<'_>>,
) -> anyhow::Result<()> {
    #[cfg(not(feature = "experimental-state-blocks"))]
    if experimental_state_blocks {
        bail!("experimental Authority templates require an experimental-state-blocks vosx build");
    }
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
    // Validate every role input before creating output or launching guest
    // compilation. These signed templates feed the one coherent repin and
    // released-role selection; materialization alone is not a release gate.
    let roles = runtime_roles
        .map(|inputs| prepare_runtime_role_templates(inputs, experimental_state_blocks))
        .transpose()?;
    fs::create_dir_all(nonempty_parent(out))?;
    fs::create_dir(out).context("create fresh system-template output")?;
    let signer = system_template_signer()?;
    for name in ["system-authority", "system-catalog"] {
        super::build::run_with_signer(
            super::build::Args {
                program: source.join("actors").join(name),
                features: if experimental_state_blocks && name == "system-authority" {
                    vec!["experimental-state-blocks".into()]
                } else {
                    vec![]
                },
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
    if let Some(roles) = roles {
        fs::write(out.join(SYSTEM_IMAGE_RUNTIME_FILE), &roles.system_image)
            .context("write System IMAGE runtime template")?;
        fs::write(
            out.join(SHARED_EXTERNAL_RUNTIME_FILE),
            &roles.shared_external,
        )
        .context("write Shared EXTERNAL runtime template")?;
        println!("prepared separately signed System IMAGE and Shared EXTERNAL runtime templates");
        println!("OPEN: exact role repin, released selection and workload/recovery qualification");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RuntimeRoleTemplateInputs<'a> {
    system_image: &'a Path,
    shared_external: &'a Path,
    external_limits: &'a Path,
}

fn runtime_role_inputs<'a>(
    system_image: Option<&'a Path>,
    shared_external: Option<&'a Path>,
    external_limits: Option<&'a Path>,
) -> anyhow::Result<Option<RuntimeRoleTemplateInputs<'a>>> {
    match (system_image, shared_external, external_limits) {
        (None, None, None) => Ok(None),
        (Some(system_image), Some(shared_external), Some(external_limits)) => {
            Ok(Some(RuntimeRoleTemplateInputs {
                system_image,
                shared_external,
                external_limits,
            }))
        }
        _ => bail!(
            "System IMAGE, Shared EXTERNAL and explicit external limits must be supplied together"
        ),
    }
}

#[cfg(any(feature = "experimental-state-blocks", test))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRoleExternalLimits {
    max_rows_per_lane: u64,
    max_row_bytes_per_lane: u64,
}

#[cfg(any(feature = "experimental-state-blocks", test))]
impl RuntimeRoleExternalLimits {
    fn signed_limits(
        self,
    ) -> anyhow::Result<vos::agent::sdk::contract::ExternalStateResourceLimits> {
        let limits = vos::agent::sdk::contract::ExternalStateResourceLimits {
            max_rows_per_lane: self.max_rows_per_lane,
            max_row_bytes_per_lane: self.max_row_bytes_per_lane,
        };
        if !limits.is_valid() {
            bail!("external runtime limits must both be positive");
        }
        Ok(limits)
    }
}

#[derive(Debug)]
struct RuntimeRoleTemplates {
    system_image: Vec<u8>,
    shared_external: Vec<u8>,
}

fn prepare_runtime_role_templates(
    inputs: RuntimeRoleTemplateInputs<'_>,
    experimental_state_blocks: bool,
) -> anyhow::Result<RuntimeRoleTemplates> {
    if !experimental_state_blocks {
        bail!("paired runtime roles require experimental-state-blocks artifact tooling");
    }
    #[cfg(not(feature = "experimental-state-blocks"))]
    {
        let _ = inputs;
        bail!("paired runtime roles require an experimental-state-blocks vosx build");
    }
    #[cfg(feature = "experimental-state-blocks")]
    {
        use vos::agent::package_admission::{admit_runtime_package, admit_state_runtime_package};
        use vos::agent::sdk::contract::RuntimePackageContract;
        use vos::agent::sdk::{LaneSet, ProofSystemSet, RuntimeCapabilities, StateLane};

        let limits_bytes = read_regular_bounded(inputs.external_limits, MAX_EXTERNAL_LIMITS_BYTES)?;
        let limits = serde_json::from_slice::<RuntimeRoleExternalLimits>(&limits_bytes)
            // serde errors may echo unknown key names. Invalid input can be
            // a mistakenly supplied credential file; do not disclose it.
            .map_err(|_| {
                anyhow::anyhow!("external runtime limits must be a strict two-field JSON object")
            })?
            .signed_limits()?;
        let system_pvm = read_regular_bounded(inputs.system_image, MAX_ARTIFACT_BYTES)?;
        let external_pvm = read_regular_bounded(inputs.shared_external, MAX_ARTIFACT_BYTES)?;
        anyhow::ensure!(
            system_pvm != external_pvm,
            "System and Shared runtime inputs must not alias"
        );
        // Reuse the actual guest probes, not merely a syntactically signed
        // contract which could mislabel an IMAGE guest as EXTERNAL or vice versa.
        super::agent_runtime_pvm::validate_system_observation_runtime_pvm(&system_pvm)
            .context("qualify System IMAGE guest ABI")?;
        super::agent_runtime_pvm::validate_state_runtime_pvm(&external_pvm)
            .context("qualify Shared EXTERNAL guest ABI")?;
        let signer = system_template_signer()?;
        let system_image = bundled::root_signed_runtime_package_bytes(
            &signer,
            &system_pvm,
            "system-image-runtime",
            RuntimePackageContract::system_observation_image(),
            RuntimeCapabilities::standard(),
            None,
        )?;
        let shared_external = bundled::root_signed_runtime_package_bytes(
            &signer,
            &external_pvm,
            "shared-external-runtime",
            RuntimePackageContract::experimental_state_blocks(),
            RuntimeCapabilities {
                lanes: LaneSet::of(StateLane::Linear),
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
                ..RuntimeCapabilities::standard()
            },
            Some(limits),
        )?;
        validate_runtime_role_templates(&system_image, &shared_external)?;
        let image =
            admit_runtime_package(&system_image).context("admit signed System IMAGE template")?;
        let external = admit_state_runtime_package(&shared_external)
            .context("admit signed Shared EXTERNAL template")?;
        anyhow::ensure!(
            image.program_bytes() == system_pvm
                && external.program_bytes() == external_pvm
                && external.external_state_limits() == limits,
            "runtime role signing changed its admitted closure or limits",
        );
        Ok(RuntimeRoleTemplates {
            system_image,
            shared_external,
        })
    }
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
    let authority = bundled::system_authority_package_template();
    validate_authority(authority)?;
    let catalog = bundled::system_catalog_package_template();
    validate_catalog(&catalog)?;
    // Both exact role pins are mandatory. The checked getters refuse while
    // qualification/repin is incomplete, before any output is created.
    let system_image = bundled::system_image_runtime_package_template()?;
    let shared_external = bundled::shared_external_runtime_package_template()?;
    validate_runtime_role_templates(system_image, shared_external)?;
    let manifest = manifest_for(
        standard_runtime,
        system_image,
        shared_external,
        authority,
        catalog,
    )?;

    let parent = nonempty_parent(output);
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    // `create_dir` is the no-clobber activation point. Building in a sibling
    // and calling ordinary `rename` would have a TOCTOU window in which an
    // empty destination created by another operator could be replaced.
    fs::create_dir(output).with_context(|| format!("reserve {}", output.display()))?;
    let mut guard = PartialDirectory(Some(output.to_path_buf()));
    fs::write(output.join(STANDARD_RUNTIME_FILE), standard_runtime)
        .context("write canonical standard runtime")?;
    fs::write(output.join(SYSTEM_IMAGE_RUNTIME_FILE), system_image)
        .context("write canonical System observation runtime template")?;
    fs::write(output.join(SHARED_EXTERNAL_RUNTIME_FILE), shared_external)
        .context("write canonical Shared external runtime template")?;
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
        "  system_image_runtime_program_id = {}",
        manifest.system_image_runtime.program_id
    );
    println!(
        "  shared_external_runtime_program_id = {}",
        manifest.shared_external_runtime.program_id
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
    let system_image = read_regular_bounded(
        &directory.join(SYSTEM_IMAGE_RUNTIME_FILE),
        MAX_ARTIFACT_BYTES,
    )?;
    let shared_external = read_regular_bounded(
        &directory.join(SHARED_EXTERNAL_RUNTIME_FILE),
        MAX_ARTIFACT_BYTES,
    )?;
    let authority = read_regular_bounded(&directory.join(AUTHORITY_FILE), MAX_ARTIFACT_BYTES)?;
    let catalog = read_regular_bounded(&directory.join(CATALOG_FILE), MAX_ARTIFACT_BYTES)?;
    validate_standard_runtime(&standard_runtime)?;
    anyhow::ensure!(
        system_image == bundled::system_image_runtime_package_template()?
            && shared_external == bundled::shared_external_runtime_package_template()?,
        "runtime role templates do not match the exact canonical release bytes"
    );
    validate_runtime_role_templates(&system_image, &shared_external)?;
    validate_authority(&authority)?;
    validate_catalog(&catalog)?;
    validate_manifest(
        &manifest,
        &standard_runtime,
        &system_image,
        &shared_external,
        &authority,
        &catalog,
    )?;
    Ok(manifest)
}

fn validate_manifest(
    manifest: &ReleaseManifest,
    standard_runtime: &[u8],
    system_image: &[u8],
    shared_external: &[u8],
    authority: &[u8],
    catalog: &[u8],
) -> anyhow::Result<()> {
    let expected = manifest_for(
        standard_runtime,
        system_image,
        shared_external,
        authority,
        catalog,
    )?;
    if manifest != &expected {
        bail!("release manifest does not describe the exact pinned artifacts");
    }
    Ok(())
}

fn validate_authority(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::system_authority_package_template();
    if bytes != canonical {
        bail!("authority package does not match the canonical release bytes");
    }
    validate_actor_package(bytes, "system-authority")?;
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

fn validate_catalog(bytes: &[u8]) -> anyhow::Result<()> {
    let canonical = bundled::system_catalog_package_template();
    if bytes != canonical {
        bail!("catalog package does not match the canonical release bytes");
    }
    validate_actor_package(bytes, "system-catalog")
}

fn validate_standard_runtime_program(bytes: &[u8]) -> anyhow::Result<()> {
    vos_pvm::spi::validate_refine_host_calls(bytes).map_err(|error| {
        anyhow::anyhow!("AgentRuntime outer host-call surface is invalid: {error:?}")
    })
}

/// Exact typed role admission, reused by source materialization and pinned
/// release verification. Signature/closure admission is not a guest probe;
/// actual ABI qualification remains mandatory before these pins are assigned.
fn validate_runtime_role_templates(
    system_image: &[u8],
    shared_external: &[u8],
) -> anyhow::Result<()> {
    #[cfg(not(feature = "experimental-state-blocks"))]
    {
        let _ = (system_image, shared_external);
        bail!(
            "System observation and Shared external release roles require experimental-state-blocks support"
        );
    }
    #[cfg(feature = "experimental-state-blocks")]
    {
        use vos::agent::package_admission::{admit_runtime_package, admit_state_runtime_package};
        use vos::agent::sdk::contract::RuntimePackageContract;
        use vos::agent::sdk::{LaneSet, RuntimeCapabilities, StateLane};

        let image = admit_runtime_package(system_image)
            .context("admit signed System observation runtime template")?;
        let external = admit_state_runtime_package(shared_external)
            .context("admit signed Shared external runtime template")?;
        let expected_external = RuntimeCapabilities {
            lanes: LaneSet::of(StateLane::Linear),
            ..RuntimeCapabilities::standard()
        };
        let public = system_template_signer()?
            .public()
            .try_into_ed25519()
            .map_err(|_| anyhow::anyhow!("template signer is not Ed25519"))?
            .to_bytes();
        anyhow::ensure!(
            image.manifest().name == "system-image-runtime"
                && image.manifest().contract == RuntimePackageContract::system_observation_image()
                && image.manifest().capabilities == RuntimeCapabilities::standard()
                && image.manifest().external_state_limits.is_none()
                && image.manifest().signing.public_key == public
                && external.manifest().name == "shared-external-runtime"
                && external.manifest().contract
                    == RuntimePackageContract::experimental_state_blocks()
                && external.manifest().capabilities == expected_external
                && external.external_state_limits().is_valid()
                && external.manifest().signing.public_key == public
                && image.program() != external.program(),
            "signed runtime templates do not implement the exact System/Shared release roles"
        );
        Ok(())
    }
}

fn validate_actor_package(bytes: &[u8], label: &str) -> anyhow::Result<()> {
    let actor = vos::agent::package_admission::admit_actor_package(bytes)
        .with_context(|| format!("admit {label} package template"))?;
    if actor.manifest().name != label {
        bail!("system package template has the wrong actor name");
    }
    if !actor
        .requirements()
        .supported_by(vos::agent::sdk::AgentProfile::Shared)
    {
        bail!("system package template requires an unsupported profile");
    }
    actor
        .envelope()
        .require_compatible_with(
            vos::agent::sdk::contract::RuntimePackageContract::canonical(),
            vos::agent::sdk::RuntimeCapabilities::standard(),
        )
        .context("system package template is incompatible with the standard runtime")?;
    vos_pvm::spi::parse_standard_program(actor.program_bytes())
        .ok_or_else(|| anyhow::anyhow!("{label} is not a canonical actor PVM program"))?;
    Ok(())
}

fn manifest_for(
    standard_runtime: &[u8],
    system_image: &[u8],
    shared_external: &[u8],
    authority: &[u8],
    catalog: &[u8],
) -> anyhow::Result<ReleaseManifest> {
    Ok(ReleaseManifest {
        format: RELEASE_FORMAT.into(),
        agent_execution_semantics: hex::encode(vos::agent::EXECUTION_SEMANTICS_ID.0),
        standard_runtime: artifact(
            ReleaseArtifactKind::AgentRuntime,
            STANDARD_RUNTIME_FILE,
            standard_runtime,
        ),
        system_image_runtime: runtime_package_artifact(SYSTEM_IMAGE_RUNTIME_FILE, system_image)?,
        shared_external_runtime: runtime_package_artifact(
            SHARED_EXTERNAL_RUNTIME_FILE,
            shared_external,
        )?,
        authority_actor: package_artifact(AUTHORITY_FILE, authority)?,
        catalog_actor: package_artifact(CATALOG_FILE, catalog)?,
    })
}

fn runtime_package_artifact(file: &str, bytes: &[u8]) -> anyhow::Result<ReleaseArtifact> {
    use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
    let envelope = PackageEnvelope::decode(bytes).context("decode release runtime template")?;
    let PackageManifest::AgentRuntime(manifest) = &envelope.manifest else {
        bail!("release runtime template has the wrong package kind");
    };
    let program = envelope
        .artifacts
        .iter()
        .find(|artifact| artifact.identity == manifest.outer_program)
        .ok_or_else(|| anyhow::anyhow!("release runtime template lacks its exact outer program"))?;
    let mut result = artifact(
        ReleaseArtifactKind::AgentRuntimePackageTemplate,
        file,
        bytes,
    );
    // The complete signed envelope digest binds the role contract/capabilities
    // and external limits. Program identity remains the enclosed PVM identity.
    result.program_id = hex::encode(AgentProgramId::of_pvm(&program.bytes).0);
    Ok(result)
}

fn package_artifact(file: &str, bytes: &[u8]) -> anyhow::Result<ReleaseArtifact> {
    let package = vos::agent::package_admission::admit_actor_package(bytes)
        .context("admit release package template")?;
    let mut result = artifact(ReleaseArtifactKind::ActorPackageTemplate, file, bytes);
    // Identity belongs to the enclosed program, not the signed envelope.
    result.program_id = hex::encode(AgentProgramId::of_pvm(package.program_bytes()).0);
    Ok(result)
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
    let mut seen = [false; 6];
    let mut count = 0usize;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read release directory {}", directory.display()))?
    {
        let entry = entry.context("read release directory entry")?;
        count += 1;
        if count > seen.len() {
            bail!(
                "release directory must contain exactly {MANIFEST_FILE}, {STANDARD_RUNTIME_FILE}, {SYSTEM_IMAGE_RUNTIME_FILE}, {SHARED_EXTERNAL_RUNTIME_FILE}, {AUTHORITY_FILE}, and {CATALOG_FILE}",
            );
        }
        let name = entry.file_name();
        let index = match name.to_str() {
            Some(MANIFEST_FILE) => 0,
            Some(STANDARD_RUNTIME_FILE) => 1,
            Some(AUTHORITY_FILE) => 2,
            Some(CATALOG_FILE) => 3,
            Some(SYSTEM_IMAGE_RUNTIME_FILE) => 4,
            Some(SHARED_EXTERNAL_RUNTIME_FILE) => 5,
            Some(_) => bail!("release directory contains an unexpected entry"),
            None => bail!("release contains a non-UTF-8 file name"),
        };
        if std::mem::replace(&mut seen[index], true) {
            bail!("release directory contains a duplicate entry");
        }
    }
    if count != seen.len() || !seen.into_iter().all(|present| present) {
        bail!(
            "release directory must contain exactly {MANIFEST_FILE}, {STANDARD_RUNTIME_FILE}, {SYSTEM_IMAGE_RUNTIME_FILE}, {SHARED_EXTERNAL_RUNTIME_FILE}, {AUTHORITY_FILE}, and {CATALOG_FILE}",
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

    #[test]
    #[ignore = "requires independently built candidate system templates"]
    fn candidate_catalog_preserves_manifest_and_nonprogram_artifacts() {
        use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
        let directory = PathBuf::from(
            std::env::var_os("VOS_AGENT_TEMPLATE_CANDIDATES")
                .expect("set candidate template directory"),
        );
        let candidate = fs::read(directory.join(CATALOG_FILE)).unwrap();
        vos::agent::package_admission::admit_actor_package(&candidate).unwrap();
        let mut previous =
            PackageEnvelope::decode(bundled::system_catalog_package_template()).unwrap();
        let mut current = PackageEnvelope::decode(&candidate).unwrap();
        let (PackageManifest::Actor(old), PackageManifest::Actor(new)) =
            (&mut previous.manifest, &current.manifest)
        else {
            panic!("Catalog must be an actor");
        };
        let old_program = old.program.clone();
        let new_program = new.program.clone();
        old.program = new.program.clone();
        old.signing = new.signing.clone();
        assert_eq!(
            &*old, new,
            "Catalog manifest changed beyond program/signature"
        );
        previous
            .artifacts
            .retain(|artifact| artifact.identity != old_program);
        current
            .artifacts
            .retain(|artifact| artifact.identity != new_program);
        assert_eq!(
            previous.artifacts, current.artifacts,
            "Catalog schema/policy/constructor artifacts changed"
        );
    }

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
    fn runtime_role_inputs_are_all_or_none() {
        let image = Path::new("system-image.pvm");
        let external = Path::new("shared-external.pvm");
        let limits = Path::new("limits.json");
        assert!(runtime_role_inputs(None, None, None).unwrap().is_none());
        let complete = runtime_role_inputs(Some(image), Some(external), Some(limits))
            .unwrap()
            .unwrap();
        assert_eq!(complete.system_image, image);
        assert_eq!(complete.shared_external, external);
        assert_eq!(complete.external_limits, limits);
        for mask in 1..7 {
            assert!(
                runtime_role_inputs(
                    (mask & 1 != 0).then_some(image),
                    (mask & 2 != 0).then_some(external),
                    (mask & 4 != 0).then_some(limits),
                )
                .is_err(),
                "partial role input mask {mask} must fail",
            );
        }
    }

    #[test]
    fn runtime_role_external_limits_are_explicit_and_strict() {
        let valid = serde_json::from_str::<RuntimeRoleExternalLimits>(
            r#"{"max_rows_per_lane":23,"max_row_bytes_per_lane":4096}"#,
        )
        .unwrap()
        .signed_limits()
        .unwrap();
        assert_eq!(valid.max_rows_per_lane, 23);
        assert_eq!(valid.max_row_bytes_per_lane, 4096);
        for json in [
            "{}",
            r#"{"max_rows_per_lane":23}"#,
            r#"{"max_rows_per_lane":23,"max_row_bytes_per_lane":4096,"extra":1}"#,
            r#"{"max_rows_per_lane":0,"max_row_bytes_per_lane":4096}"#,
            r#"{"max_rows_per_lane":23,"max_row_bytes_per_lane":0}"#,
            r#"{"max_rows_per_lane":-1,"max_row_bytes_per_lane":4096}"#,
            r#"{"max_rows_per_lane":23,"max_rows_per_lane":24,"max_row_bytes_per_lane":4096}"#,
            r#"{"max_rows_per_lane":18446744073709551616,"max_row_bytes_per_lane":4096}"#,
        ] {
            let decoded = serde_json::from_str::<RuntimeRoleExternalLimits>(json);
            assert!(
                decoded
                    .and_then(|limits| { limits.signed_limits().map_err(serde::de::Error::custom) })
                    .is_err(),
                "invalid or implicit limits must fail: {json}",
            );
        }
    }

    #[test]
    fn runtime_role_limits_are_bounded_without_disclosing_invalid_input() {
        let directory = TestDir::new("role-limits-bound");
        let limits = directory.0.join("limits.json");
        let sensitive = vec![b'x'; MAX_EXTERNAL_LIMITS_BYTES as usize + 1];
        fs::write(&limits, &sensitive).unwrap();
        let error = read_regular_bounded(&limits, MAX_EXTERNAL_LIMITS_BYTES).unwrap_err();
        assert!(error.to_string().contains("invalid size"));
        assert!(!error.to_string().contains("xxxxx"));
        assert_eq!(fs::read(limits).unwrap(), sensitive);
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn invalid_runtime_role_inputs_never_create_template_output() {
        let source = TestDir::new("invalid-role-source");
        for actor in ["system-authority", "system-catalog"] {
            let path = source.0.join("actors").join(actor);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("Cargo.toml"), b"unused invalid-input fixture").unwrap();
        }
        let image = source.0.join("image.pvm");
        let external = source.0.join("external.pvm");
        let limits = source.0.join("limits.json");
        fs::write(&image, b"not a PVM").unwrap();
        fs::write(&external, b"not an external PVM").unwrap();
        let sensitive = b"not JSON: signer material must not be copied to output";
        fs::write(&limits, sensitive).unwrap();
        let inputs = RuntimeRoleTemplateInputs {
            system_image: &image,
            shared_external: &external,
            external_limits: &limits,
        };
        let out = source.0.join("new-output");
        let error = build_system_templates(&source.0, &out, true, Some(inputs)).unwrap_err();
        assert!(!error.to_string().contains("signer material"));
        assert!(!out.exists());
        assert_eq!(fs::read(&limits).unwrap(), sensitive);
        fs::write(
            &limits,
            br#"{"SECRET_MUST_NOT_APPEAR_IN_ERRORS":1,"max_rows_per_lane":23,"max_row_bytes_per_lane":4096}"#,
        ).unwrap();
        let error = build_system_templates(&source.0, &out, true, Some(inputs)).unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET_MUST_NOT_APPEAR_IN_ERRORS"));
        assert!(!out.exists());
        fs::write(
            &limits,
            br#"{"max_rows_per_lane":23,"max_row_bytes_per_lane":4096}"#,
        )
        .unwrap();
        assert!(build_system_templates(&source.0, &out, true, Some(inputs)).is_err());
        assert!(!out.exists());
        // A reused image, including a hard-link alias, is not two role inputs.
        let aliases = RuntimeRoleTemplateInputs {
            shared_external: &image,
            ..inputs
        };
        assert!(
            prepare_runtime_role_templates(aliases, true)
                .unwrap_err()
                .to_string()
                .contains("alias")
        );
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    #[ignore = "requires independently reproduced coherent IMAGE/EXTERNAL runtime role inputs"]
    fn candidate_runtime_role_templates_bind_abi_capabilities_limits_and_signer() {
        use vos::agent::package_admission::{admit_runtime_package, admit_state_runtime_package};
        use vos::agent::sdk::contract::RuntimePackageContract;
        use vos::agent::sdk::package::{PackageEnvelope, PackageManifest};
        use vos::agent::sdk::{LaneSet, ProofSystemSet, StateLane};

        let image_path = PathBuf::from(
            std::env::var_os("VOS_AGENT_SYSTEM_IMAGE_RUNTIME_PVM")
                .expect("set coherent System IMAGE PVM"),
        );
        let external_path = PathBuf::from(
            std::env::var_os("VOS_AGENT_SHARED_EXTERNAL_RUNTIME_PVM")
                .expect("set coherent Shared EXTERNAL PVM"),
        );
        let limits_path = PathBuf::from(
            std::env::var_os("VOS_AGENT_RUNTIME_ROLE_LIMITS").expect("set explicit role limits"),
        );
        let inputs = RuntimeRoleTemplateInputs {
            system_image: &image_path,
            shared_external: &external_path,
            external_limits: &limits_path,
        };
        let first = prepare_runtime_role_templates(inputs, true).unwrap();
        let second = prepare_runtime_role_templates(inputs, true).unwrap();
        assert_eq!(first.system_image, second.system_image);
        assert_eq!(first.shared_external, second.shared_external);
        let image = admit_runtime_package(&first.system_image).unwrap();
        let external = admit_state_runtime_package(&first.shared_external).unwrap();
        assert_eq!(image.manifest().name, "system-image-runtime");
        assert_eq!(external.manifest().name, "shared-external-runtime");
        assert_eq!(
            image.manifest().contract,
            RuntimePackageContract::system_observation_image()
        );
        assert!(image.manifest().external_state_limits.is_none());
        assert_eq!(
            external.manifest().contract,
            RuntimePackageContract::experimental_state_blocks(),
        );
        assert_eq!(
            external.manifest().capabilities.lanes,
            LaneSet::of(StateLane::Linear)
        );
        assert!(!external.manifest().capabilities.scheduling);
        assert_eq!(
            external.manifest().capabilities.proof_systems,
            ProofSystemSet::EMPTY
        );
        assert!(admit_runtime_package(&first.shared_external).is_err());
        assert!(admit_state_runtime_package(&first.system_image).is_err());
        let public = system_template_signer()
            .unwrap()
            .public()
            .try_into_ed25519()
            .unwrap()
            .to_bytes();
        assert_eq!(image.manifest().signing.public_key, public);
        assert_eq!(external.manifest().signing.public_key, public);
        let mut forged = PackageEnvelope::decode(&first.shared_external).unwrap();
        let PackageManifest::AgentRuntime(manifest) = &mut forged.manifest else {
            unreachable!()
        };
        let rows = &mut manifest
            .external_state_limits
            .as_mut()
            .unwrap()
            .max_rows_per_lane;
        *rows = if *rows == u64::MAX {
            *rows - 1
        } else {
            *rows + 1
        };
        assert!(admit_state_runtime_package(&forged.encode().unwrap()).is_err());
        // A typed contract label alone cannot make the other physical guest
        // implement that ABI. The same existing probes must reject swapped roles.
        assert!(
            super::super::agent_runtime_pvm::validate_state_runtime_pvm(image.program_bytes(),)
                .is_err()
        );
        assert!(
            super::super::agent_runtime_pvm::validate_system_observation_runtime_pvm(
                external.program_bytes(),
            )
            .is_err()
        );
        validate_standard_runtime(bundled::agent_runtime_pvm()).unwrap();
    }

    #[test]
    fn system_templates_reject_existing_output_without_modifying_it() {
        let out = TestDir::new("templates-existing");
        let sentinel = out.0.join("keep");
        fs::write(&sentinel, b"unchanged").unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert!(build_system_templates(source, &out.0, false, None).is_err());
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
    }

    #[test]
    fn system_templates_validate_source_before_creating_output() {
        let source = TestDir::new("templates-missing-source");
        let out = source.0.join("output");
        assert!(build_system_templates(&source.0, &out, false, None).is_err());
        assert!(!out.exists());
    }

    #[cfg(not(feature = "experimental-state-blocks"))]
    #[test]
    fn default_binary_refuses_experimental_template_build() {
        let source = TestDir::new("templates-experimental-disabled");
        let out = source.0.join("output");
        assert!(
            build_system_templates(&source.0, &out, true, None)
                .unwrap_err()
                .to_string()
                .contains("experimental-state-blocks vosx build")
        );
        assert!(!out.exists());
    }

    #[test]
    fn manifest_binds_execution_semantics_kinds_and_all_artifacts() {
        let manifest = fixture_manifest();
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
        assert_eq!(
            manifest.system_image_runtime.file,
            SYSTEM_IMAGE_RUNTIME_FILE
        );
        assert_eq!(
            manifest.shared_external_runtime.file,
            SHARED_EXTERNAL_RUNTIME_FILE
        );
        assert_eq!(
            manifest.system_image_runtime.kind,
            ReleaseArtifactKind::AgentRuntimePackageTemplate
        );
        assert_eq!(
            manifest.shared_external_runtime.kind,
            ReleaseArtifactKind::AgentRuntimePackageTemplate
        );
        assert_eq!(manifest.authority_actor.file, AUTHORITY_FILE);
        assert_eq!(
            manifest.authority_actor.kind,
            ReleaseArtifactKind::ActorPackageTemplate
        );
        assert_eq!(manifest.catalog_actor.file, CATALOG_FILE);
        assert_eq!(
            manifest.catalog_actor.kind,
            ReleaseArtifactKind::ActorPackageTemplate
        );
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
        let manifest = fixture_manifest();
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
    fn release_manifest_requires_both_signed_runtime_roles() {
        let value = serde_json::to_value(fixture_manifest()).unwrap();
        for missing in ["system_image_runtime", "shared_external_runtime"] {
            let mut incomplete = value.clone();
            incomplete.as_object_mut().unwrap().remove(missing);
            assert!(serde_json::from_value::<ReleaseManifest>(incomplete).is_err());
        }
        let (image, external) = fixture_runtime_templates();
        assert!(
            validate_runtime_role_templates(&image, &external).is_err(),
            "ordinary Local images cannot be relabeled as released System/Shared roles"
        );
    }

    #[test]
    fn runtime_manifest_binds_signed_envelope_not_only_enclosed_program() {
        let (image, external) = fixture_runtime_templates();
        let manifest = fixture_manifest();
        let mut changed = vos::agent::sdk::package::PackageEnvelope::decode(&external).unwrap();
        let vos::agent::sdk::package::PackageManifest::AgentRuntime(runtime) =
            &mut changed.manifest
        else {
            unreachable!()
        };
        runtime.signing.signature[0] ^= 1;
        let changed = changed.encode().unwrap();
        assert_eq!(
            runtime_package_artifact(SHARED_EXTERNAL_RUNTIME_FILE, &external)
                .unwrap()
                .program_id,
            runtime_package_artifact(SHARED_EXTERNAL_RUNTIME_FILE, &changed)
                .unwrap()
                .program_id,
        );
        assert!(
            validate_manifest(
                &manifest,
                bundled::agent_runtime_pvm(),
                &image,
                &changed,
                bundled::system_authority_package_template(),
                bundled::system_catalog_package_template(),
            )
            .is_err()
        );
    }

    #[test]
    fn release_manifest_rejects_the_previous_agent_semantics() {
        let mut manifest = fixture_manifest();
        let (image, external) = fixture_runtime_templates();
        manifest.agent_execution_semantics = hex::encode(*b"vos-pvm-41d31e6-standard-gas-r02");
        assert!(
            validate_manifest(
                &manifest,
                bundled::agent_runtime_pvm(),
                &image,
                &external,
                bundled::system_authority_package_template(),
                bundled::system_catalog_package_template()
            )
            .is_err(),
            "a release produced for the immediately previous Agent semantics must fail closed",
        );
    }

    #[test]
    fn release_manifest_uses_one_program_identity_domain() {
        let runtime = bundled::agent_runtime_pvm();
        let authority = vos::agent::package_admission::admit_actor_package(
            bundled::system_authority_package_template(),
        )
        .unwrap();
        let catalog = vos::agent::package_admission::admit_actor_package(
            bundled::system_catalog_package_template(),
        )
        .unwrap();
        let manifest = fixture_manifest();
        assert_eq!(
            manifest.standard_runtime.program_id,
            hex::encode(AgentProgramId::of_pvm(runtime).0),
        );
        assert_eq!(
            manifest.system_image_runtime.program_id,
            manifest.standard_runtime.program_id
        );
        assert_eq!(
            manifest.shared_external_runtime.program_id,
            manifest.standard_runtime.program_id
        );
        assert_eq!(
            manifest.authority_actor.program_id,
            hex::encode(AgentProgramId::of_pvm(authority.program_bytes()).0),
        );
        assert_eq!(
            manifest.catalog_actor.program_id,
            hex::encode(AgentProgramId::of_pvm(catalog.program_bytes()).0),
        );
    }

    #[test]
    fn authority_pin_rejects_changed_bytes() {
        assert!(validate_authority(b"not the canonical authority").is_err());
    }

    #[test]
    fn bundled_authority_matches_the_runtime_release_pins() {
        let authority = bundled::system_authority_package_template();
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
    fn bundled_catalog_matches_the_exact_release_pin() {
        let catalog = bundled::system_catalog_package_template();
        validate_catalog(catalog).expect("bundled and release catalog pins must agree");
    }

    // Structural manifest tests must not invent qualified System/Shared pins.
    // Ordinary canonical signed images only exercise envelope/program digest
    // binding here; typed role admission rejects these fixtures explicitly.
    fn fixture_runtime_templates() -> (Vec<u8>, Vec<u8>) {
        use vos::agent::sdk::RuntimeCapabilities;
        use vos::agent::sdk::contract::RuntimePackageContract;
        let signer = system_template_signer().unwrap();
        let package = |name| {
            bundled::root_signed_runtime_package_bytes(
                &signer,
                bundled::agent_runtime_pvm(),
                name,
                RuntimePackageContract::canonical(),
                RuntimeCapabilities::standard(),
                None,
            )
            .unwrap()
        };
        (
            package("system-image-runtime"),
            package("shared-external-runtime"),
        )
    }

    fn fixture_manifest() -> ReleaseManifest {
        let (image, external) = fixture_runtime_templates();
        manifest_for(
            bundled::agent_runtime_pvm(),
            &image,
            &external,
            bundled::system_authority_package_template(),
            bundled::system_catalog_package_template(),
        )
        .unwrap()
    }

    #[test]
    fn release_rejects_legacy_programs_and_previous_format() {
        assert!(validate_authority(bundled::space_authority_pvm().unwrap()).is_err());
        assert!(validate_catalog(bundled::registry_elf().unwrap()).is_err());
        let mut manifest = fixture_manifest();
        let (image, external) = fixture_runtime_templates();
        manifest.format = "VOS-AGENT-RELEASE-1".into();
        assert!(
            validate_manifest(
                &manifest,
                bundled::agent_runtime_pvm(),
                &image,
                &external,
                bundled::system_authority_package_template(),
                bundled::system_catalog_package_template()
            )
            .is_err()
        );
    }

    #[test]
    fn bundle_requires_exact_roles_and_is_reproducible_when_pinned() {
        let temp = TestDir::new("reproducible");
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        if bundled::system_image_runtime_package_template().is_err()
            || bundled::shared_external_runtime_package_template().is_err()
        {
            assert!(bundle(&first).is_err());
            assert!(
                !first.exists(),
                "unqualified role pins must refuse before output writes"
            );
            return;
        }
        bundle(&first).expect("first bundle");
        bundle(&second).expect("second bundle");
        let first_manifest = verify(&first).expect("verify first bundle");
        let second_manifest = verify(&second).expect("verify second bundle");
        assert_eq!(first_manifest, second_manifest);
        for file in [
            MANIFEST_FILE,
            STANDARD_RUNTIME_FILE,
            SYSTEM_IMAGE_RUNTIME_FILE,
            SHARED_EXTERNAL_RUNTIME_FILE,
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

    #[test]
    fn release_bundle_refuses_existing_output_without_modifying_it() {
        let directory = TestDir::new("bundle-no-clobber");
        let sentinel = directory.0.join("keep");
        fs::write(&sentinel, b"unchanged").unwrap();
        assert!(
            bundle(&directory.0)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
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
            SYSTEM_IMAGE_RUNTIME_FILE,
            SHARED_EXTERNAL_RUNTIME_FILE,
            AUTHORITY_FILE,
            CATALOG_FILE,
            "surplus",
        ] {
            fs::write(temp.0.join(name), b"x").expect("write test entry");
        }
        assert!(verify_directory_shape(&temp.0).is_err());
    }

    #[test]
    fn release_directory_requires_both_role_packages() {
        let directory = TestDir::new("role-directory-shape");
        for name in [
            MANIFEST_FILE,
            STANDARD_RUNTIME_FILE,
            AUTHORITY_FILE,
            CATALOG_FILE,
        ] {
            fs::write(directory.0.join(name), b"x").unwrap();
        }
        assert!(verify_directory_shape(&directory.0).is_err());
        fs::write(directory.0.join(SYSTEM_IMAGE_RUNTIME_FILE), b"x").unwrap();
        assert!(verify_directory_shape(&directory.0).is_err());
        fs::write(directory.0.join(SHARED_EXTERNAL_RUNTIME_FILE), b"x").unwrap();
        verify_directory_shape(&directory.0).unwrap();
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
