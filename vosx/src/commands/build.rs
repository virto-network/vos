//! Build a canonical actor PVM and its signed `.vos` v2 package.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use vos::v2::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageManifestV2, PackageRolePoliciesV2,
    PackageTaskDependencyV2, ProducerId, ProgramId, TaskDependencyV2, V2Wire, VosPackageV2,
    artifact_hash, task_dependencies_hash,
};

const RUSTC_WRAPPER_MODE: &str = "VOSX_CANONICAL_RUSTC_WRAPPER";
const RUSTC_WRAPPER_SOURCE_ROOT: &str = "VOSX_CANONICAL_SOURCE_ROOT";
const RUSTC_UNIT_METADATA_DOMAIN: &[u8] = b"vos/rustc-unit-metadata/v2";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RustcUnitIdentity {
    package_name: OsString,
    package_version: OsString,
    package_repository: OsString,
    manifest_dir: Option<PathBuf>,
}

impl RustcUnitIdentity {
    fn from_environment() -> Self {
        Self {
            package_name: std::env::var_os("CARGO_PKG_NAME").unwrap_or_default(),
            package_version: std::env::var_os("CARGO_PKG_VERSION").unwrap_or_default(),
            package_repository: std::env::var_os("CARGO_PKG_REPOSITORY").unwrap_or_default(),
            manifest_dir: std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from),
        }
    }
}

pub struct Args {
    pub program: PathBuf,
    pub name: Option<String>,
    pub version: String,
    pub out_dir: PathBuf,
    pub interfaces: Option<PathBuf>,
    pub role_policies: Option<PathBuf>,
    pub schemas: Option<PathBuf>,
    pub source_map: Option<PathBuf>,
    pub tasks: Vec<PathBuf>,
    pub include_elf: bool,
    pub crdt: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let keypair = crate::identity::load_or_create()?;
    run_with_signer(args, &keypair)
}

fn run_with_signer(args: Args, keypair: &libp2p::identity::Keypair) -> anyhow::Result<()> {
    let program = resolve_program_input(&args.program)?;
    let input = std::fs::read(&program).with_context(|| format!("read {}", program.display()))?;
    let is_pvm = program.extension().and_then(|x| x.to_str()) == Some("pvm");
    let actor_pvm = if is_pvm {
        input.clone()
    } else {
        grey_transpiler::link_elf(&input)
            .map_err(|error| anyhow!("transpile {}: {error:?}", program.display()))?
    };
    if actor_pvm.is_empty() {
        bail!("{} produced an empty PVM", program.display());
    }
    vos::v2::validate_actor_program_layout(&actor_pvm)
        .map_err(|error| anyhow!("invalid canonical actor PVM capability layout: {error}"))?;

    let schemas = match args.schemas.as_deref() {
        Some(path) => std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        None if !is_pvm => vos::metadata::raw_section_from_elf(&input).unwrap_or_default(),
        None => Vec::new(),
    };
    let actor_metadata = vos::metadata::decode(&schemas).ok_or_else(|| {
        anyhow!(
            "{} has no valid v2 actor schema; build from its ELF or pass --schemas with exact .vos_meta bytes",
            program.display()
        )
    })?;
    if args.crdt && !actor_metadata.crdt {
        bail!(
            "{} is an ordinary actor; use #[actor(crdt)] instead of forcing --crdt",
            program.display(),
        );
    }
    let crdt = actor_metadata.crdt || args.crdt;
    let name = args
        .name
        .unwrap_or_else(|| actor_metadata.actor_name.clone());

    let interfaces = read_optional(args.interfaces.as_deref())?;
    let mut task_dependencies = args
        .tasks
        .iter()
        .map(|input| build_task_dependency(input))
        .collect::<anyhow::Result<Vec<_>>>()?;
    task_dependencies.sort_by_key(|dependency| dependency.binding.task);
    if task_dependencies
        .windows(2)
        .any(|pair| pair[0].binding.task == pair[1].binding.task)
    {
        bail!("duplicate canonical Task dependency");
    }
    let mut generated_policies = PackageRolePoliciesV2::from_metadata(&actor_metadata)?;
    generated_policies.task_dependencies = task_dependencies
        .iter()
        .map(|dependency| dependency.binding.clone())
        .collect();
    let generated_role_policies = generated_policies.encode();
    let role_policies = match args.role_policies.as_deref() {
        Some(path) => {
            let supplied =
                std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            if supplied != generated_role_policies {
                bail!(
                    "{} does not match the policies generated from the actor's .vos_meta annotations",
                    path.display()
                );
            }
            supplied
        }
        None => generated_role_policies,
    };
    let source_map = read_optional(args.source_map.as_deref())?;
    let service_program = vos::v2::VOS_SERVICE_PROGRAM_ID;
    let actor_program = ProgramId::of_pvm(&actor_pvm);

    let public_key = keypair.public().encode_protobuf();
    let producer = ProducerId::of_public_key(&public_key);
    let mut package = VosPackageV2 {
        manifest: PackageManifestV2 {
            name: name.clone(),
            version: args.version,
            service_abi: vos::v2::ABI_VERSION,
            snapshot_version: vos::v2::SNAPSHOT_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            service_program,
            actor_program,
            crdt,
            interfaces_hash: artifact_hash(b"interfaces", &interfaces),
            role_policies_hash: artifact_hash(b"role-policies", &role_policies),
            schemas_hash: artifact_hash(b"schemas", &schemas),
            task_dependencies_hash: task_dependencies_hash(&task_dependencies),
        },
        actor_pvm: actor_pvm.clone(),
        generated_interfaces: interfaces,
        role_policies,
        schemas,
        task_dependencies,
        diagnostics: (args.include_elf || !source_map.is_empty()).then_some(PackageDiagnosticsV2 {
            elf: (args.include_elf && !is_pvm).then_some(input),
            source_map: (!source_map.is_empty()).then_some(source_map),
        }),
        deployment_signature: DeploymentSignatureV2 {
            producer,
            public_key,
            signature: vec![0],
        },
    };
    package.deployment_signature.signature = keypair
        .sign(&package.signing_message())
        .map_err(|error| anyhow!("sign deployment: {error}"))?;
    package.validate()?;

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;
    let pvm_path = args.out_dir.join(format!("{name}.pvm"));
    let package_path = args.out_dir.join(format!("{name}.vos"));
    std::fs::write(&pvm_path, actor_pvm)
        .with_context(|| format!("write {}", pvm_path.display()))?;
    std::fs::write(&package_path, package.encode())
        .with_context(|| format!("write {}", package_path.display()))?;

    println!("built {}", package_path.display());
    println!("  actor_pvm    = {}", pvm_path.display());
    println!("  program_id   = {}", hex::encode(actor_program.0));
    println!(
        "  deployment_id = {}",
        hex::encode(package.deployment_id().0)
    );
    Ok(())
}

fn build_task_dependency(input: &Path) -> anyhow::Result<PackageTaskDependencyV2> {
    let program = resolve_program_input(input)?;
    if program.extension().and_then(|extension| extension.to_str()) == Some("pvm") {
        bail!(
            "{} is a PVM without authenticated witness-layout metadata; pass the canonical Task ELF or project directory",
            program.display()
        );
    }
    let elf = std::fs::read(&program).with_context(|| format!("read {}", program.display()))?;
    let pvm = grey_transpiler::link_elf(&elf)
        .map_err(|error| anyhow!("transpile Task {}: {error:?}", program.display()))?;
    if pvm.is_empty() {
        bail!("{} produced an empty Task PVM", program.display());
    }
    let (witness_address, witness_capacity) = vos::zk::witness_symbol(&elf).ok_or_else(|| {
        anyhow!(
            "{} does not export the required __VOS_WITNESS buffer",
            program.display()
        )
    })?;
    let witness_address = u32::try_from(witness_address)
        .context("Task witness address does not fit the PVM address space")?;
    let witness_capacity = u32::try_from(witness_capacity)
        .context("Task witness capacity does not fit the package wire")?;
    if witness_capacity == 0 {
        bail!(
            "{} exports an empty __VOS_WITNESS buffer",
            program.display()
        );
    }
    Ok(PackageTaskDependencyV2 {
        binding: TaskDependencyV2 {
            task: vos::v2::Hash(vos::provable::task_blob_hash(&pvm)),
            program: ProgramId::of_pvm(&pvm),
            witness_address,
            witness_capacity,
        },
        pvm,
    })
}

fn resolve_program_input(input: &Path) -> anyhow::Result<PathBuf> {
    if !input.is_dir() {
        return Ok(input.to_path_buf());
    }
    let project = std::fs::canonicalize(input)
        .with_context(|| format!("resolve actor project {}", input.display()))?;
    let manifest_path = project.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read actor manifest {}", manifest_path.display()))?;
    let (package_name, actor_target_name) = actor_names_from_manifest(&manifest)?;
    let build_root = std::fs::canonicalize(actor_build_root(&project)?)
        .with_context(|| format!("resolve actor build root for {}", input.display()))?;
    let source_root = canonical_source_root(&build_root);
    // Own the artifact location. Inheriting CARGO_TARGET_DIR or a configured
    // target-dir and then reading build_root/target could sign an unrelated
    // stale ELF even though Cargo successfully built fresh code elsewhere.
    let target_dir = build_root.join("target");
    let mut command = Command::new("cargo");
    command.args(["+nightly", "actor"]);
    if build_root != project {
        command.args(["-p", &package_name]);
    }
    command
        .env("RUSTC_WRAPPER", std::env::current_exe()?)
        .env(RUSTC_WRAPPER_MODE, "1")
        .env(RUSTC_WRAPPER_SOURCE_ROOT, &source_root)
        .env("CARGO_TARGET_DIR", &target_dir);
    let status = command
        .current_dir(&build_root)
        .status()
        .with_context(|| format!("run `cargo +nightly actor` in {}", build_root.display()))?;
    if !status.success() {
        bail!(
            "actor build failed in {} with status {status}",
            input.display()
        );
    }
    let elf = target_dir
        .join("riscv64em-javm/release")
        .join(format!("{actor_target_name}.elf"));
    if !elf.is_file() {
        bail!(
            "actor build succeeded but did not produce {}; ensure the project uses the VOS cargo actor configuration",
            elf.display()
        );
    }
    Ok(elf)
}

fn canonical_source_root(build_root: &Path) -> &Path {
    build_root
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .unwrap_or(build_root)
}

/// Cargo invokes the current `vosx` executable as a rustc wrapper while
/// compiling canonical actors. Cargo's generated `-Cmetadata` includes local
/// source paths before rustc sees remapping flags, so merely remapping paths is
/// insufficient: identical worktrees can still produce different code and
/// `ProgramId`s. Strip that generated value, install a protocol-stable one,
/// and remap the complete source repository rather than only the actor member.
pub fn maybe_run_canonical_rustc_wrapper() {
    if std::env::var_os(RUSTC_WRAPPER_MODE).is_none() {
        return;
    }
    let mut arguments = std::env::args_os().skip(1);
    let Some(rustc) = arguments.next() else {
        eprintln!("vosx canonical rustc wrapper: missing rustc executable");
        std::process::exit(1);
    };
    let Some(source_root) = std::env::var_os(RUSTC_WRAPPER_SOURCE_ROOT) else {
        eprintln!("vosx canonical rustc wrapper: missing source root");
        std::process::exit(1);
    };
    let arguments = arguments.collect::<Vec<_>>();
    let unit = RustcUnitIdentity::from_environment();
    let status = Command::new(rustc)
        .args(canonical_rustc_arguments(arguments, &source_root, &unit))
        .status();
    match status {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("vosx canonical rustc wrapper: {error}");
            std::process::exit(1);
        }
    }
}

fn canonical_rustc_arguments(
    arguments: impl IntoIterator<Item = OsString>,
    source_root: &OsStr,
    unit: &RustcUnitIdentity,
) -> Vec<OsString> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let metadata = canonical_rustc_unit_metadata(&arguments, source_root, unit);
    let mut arguments = arguments.into_iter().peekable();
    let mut canonical = Vec::new();
    while let Some(argument) = arguments.next() {
        if argument == "-C"
            && arguments
                .peek()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with("metadata="))
        {
            arguments.next();
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|value| value.starts_with("-Cmetadata="))
        {
            continue;
        }
        canonical.push(argument);
    }
    canonical.push(OsString::from(format!("-Cmetadata={metadata}")));
    let mut remap = OsString::from("--remap-path-prefix=");
    remap.push(source_root);
    remap.push("=vos-source");
    canonical.push(remap);
    canonical
}

/// Derive rustc's crate disambiguator from stable Cargo-unit inputs.
///
/// Cargo's own metadata contains absolute path-package identities, so it
/// cannot be used verbatim for canonical builds. A single replacement for
/// every crate is also invalid: two versions or sources of the same crate
/// would receive the same StableCrateId. This digest keeps the unit identity
/// while normalizing checkout- and Cargo-home-dependent paths.
fn canonical_rustc_unit_metadata(
    arguments: &[OsString],
    source_root: &OsStr,
    unit: &RustcUnitIdentity,
) -> String {
    let source_root = Path::new(source_root);
    let mut identity = Vec::new();
    push_metadata_part(
        &mut identity,
        b"package-name",
        unit.package_name.as_os_str(),
    );
    push_metadata_part(
        &mut identity,
        b"package-version",
        unit.package_version.as_os_str(),
    );
    push_metadata_part(
        &mut identity,
        b"package-repository",
        unit.package_repository.as_os_str(),
    );
    let package_source = unit
        .manifest_dir
        .as_deref()
        .map(|manifest_dir| canonical_package_source(manifest_dir, source_root))
        .unwrap_or_else(|| OsString::from("cargo-package-unknown"));
    push_metadata_part(&mut identity, b"package-source", &package_source);

    let mut arguments = arguments.iter().peekable();
    while let Some(argument) = arguments.next() {
        if argument == "-C"
            && arguments
                .peek()
                .and_then(|value| value.to_str())
                .is_some_and(|value| {
                    value.starts_with("metadata=") || value.starts_with("extra-filename=")
                })
        {
            arguments.next();
            continue;
        }
        if argument.to_str().is_some_and(|value| {
            value.starts_with("-Cmetadata=") || value.starts_with("-Cextra-filename=")
        }) {
            continue;
        }
        if argument == "--extern" {
            if let Some(extern_crate) = arguments.next() {
                let extern_crate = extern_crate.to_string_lossy();
                let name = extern_crate
                    .split_once('=')
                    .map_or(extern_crate.as_ref(), |(name, _)| name);
                push_metadata_part(&mut identity, b"rustc-extern", OsStr::new(name));
            }
            continue;
        }
        if let Some(extern_crate) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--extern="))
        {
            let name = extern_crate
                .split_once('=')
                .map_or(extern_crate, |(name, _)| name);
            push_metadata_part(&mut identity, b"rustc-extern", OsStr::new(name));
            continue;
        }
        let normalized =
            normalize_rustc_argument(argument, source_root, unit.manifest_dir.as_deref());
        push_metadata_part(&mut identity, b"rustc-argument", &normalized);
    }

    let hash = vos::crypto::blake2b_hash::<16>(RUSTC_UNIT_METADATA_DOMAIN, &[&identity]);
    format!("vos-actor-v2-{}", hex::encode(hash))
}

fn push_metadata_part(output: &mut Vec<u8>, label: &[u8], value: &OsStr) {
    push_metadata_bytes(output, label);
    push_metadata_bytes(output, value.to_string_lossy().as_bytes());
}

fn push_metadata_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn normalize_rustc_argument(
    argument: &OsStr,
    source_root: &Path,
    manifest_dir: Option<&Path>,
) -> OsString {
    let mut value = argument.to_string_lossy().replace('\\', "/");
    let source_root = source_root.to_string_lossy().replace('\\', "/");
    if !source_root.is_empty() {
        value = value.replace(&source_root, "vos-source");
    }
    if let Some(manifest_dir) = manifest_dir {
        let manifest_dir = manifest_dir.to_string_lossy().replace('\\', "/");
        if !manifest_dir.is_empty()
            && Path::new(manifest_dir.as_str())
                .strip_prefix(source_root.as_str())
                .is_err()
        {
            value = value.replace(&manifest_dir, "vos-package");
        }
    }
    OsString::from(value)
}

fn canonical_package_source(manifest_dir: &Path, source_root: &Path) -> OsString {
    if let Ok(relative) = manifest_dir.strip_prefix(source_root) {
        return OsString::from(format!(
            "workspace/{}",
            relative.to_string_lossy().replace('\\', "/")
        ));
    }

    let normalized = manifest_dir.to_string_lossy().replace('\\', "/");
    for marker in ["/registry/src/", "/git/checkouts/"] {
        if let Some(index) = normalized.find(marker) {
            // The suffix contains Cargo's stable registry/repository identity
            // and package/checkout identity, but not CARGO_HOME.
            return OsString::from(format!("cargo/{}", &normalized[index + marker.len()..]));
        }
    }

    // Toolchain and unusual external path packages have no stable absolute
    // location. Package name/version/repository and normalized rustc inputs
    // still distinguish their compilation units without embedding that path.
    OsString::from("external")
}

fn actor_build_root(project: &Path) -> anyhow::Result<PathBuf> {
    project
        .ancestors()
        .find(|candidate| {
            candidate.join(".cargo/config.toml").is_file()
                && candidate.join("riscv64em-javm.json").is_file()
        })
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "{} is missing the VOS .cargo/config.toml and riscv64em-javm.json build configuration",
                project.display()
            )
        })
}

fn actor_names_from_manifest(manifest: &str) -> anyhow::Result<(String, String)> {
    let manifest: toml::Value = manifest
        .parse()
        .map_err(|error| anyhow!("parse actor Cargo.toml: {error}"))?;
    let package_name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("actor Cargo.toml needs a non-empty [package].name"))?;
    let target_name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .unwrap_or_else(|| package_name.replace('-', "_"));
    Ok((package_name, target_name))
}

fn read_optional(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    path.map(std::fs::read)
        .transpose()
        .map(|bytes| bytes.unwrap_or_default())
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "vosx-v2-build-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn canonical_wrapper_replaces_path_dependent_cargo_metadata() {
        let unit = RustcUnitIdentity {
            package_name: "counter".into(),
            package_version: "1.0.0".into(),
            manifest_dir: Some("/checkout/actors/counter".into()),
            ..Default::default()
        };
        let arguments = [
            "--crate-name",
            "counter",
            "-C",
            "metadata=checkout-specific",
            "-Cmetadata=also-checkout-specific",
            "--emit=link",
        ]
        .map(OsString::from);
        let canonical = canonical_rustc_arguments(arguments, OsStr::new("/checkout"), &unit);
        assert_eq!(&canonical[..3], ["--crate-name", "counter", "--emit=link"]);
        assert!(
            canonical[3]
                .to_string_lossy()
                .starts_with("-Cmetadata=vos-actor-v2-")
        );
        assert_eq!(canonical[4], "--remap-path-prefix=/checkout=vos-source");
    }

    #[test]
    fn canonical_metadata_is_checkout_independent() {
        let arguments = |checkout: &str| {
            [
                "--crate-name".into(),
                "counter".into(),
                format!("{checkout}/actors/counter/src/lib.rs").into(),
                "--out-dir".into(),
                format!("{checkout}/target/release/deps").into(),
                "-Cmetadata=checkout-specific".into(),
                format!("-Cextra-filename=-{}", checkout.trim_start_matches('/')).into(),
                "--extern".into(),
                format!("vos={checkout}/target/release/deps/libvos-checkout.rlib").into(),
                "--cfg".into(),
                "feature=\"default\"".into(),
            ]
        };
        let unit = |checkout: &str| RustcUnitIdentity {
            package_name: "counter".into(),
            package_version: "1.0.0".into(),
            manifest_dir: Some(format!("{checkout}/actors/counter").into()),
            ..Default::default()
        };
        assert_eq!(
            canonical_rustc_unit_metadata(
                &arguments("/checkout-a"),
                OsStr::new("/checkout-a"),
                &unit("/checkout-a"),
            ),
            canonical_rustc_unit_metadata(
                &arguments("/checkout-b"),
                OsStr::new("/checkout-b"),
                &unit("/checkout-b"),
            ),
        );
    }

    #[test]
    fn canonical_metadata_distinguishes_cargo_units() {
        let arguments = ["--crate-name", "shared", "src/lib.rs"].map(OsString::from);
        let unit = |version: &str, source: &str| RustcUnitIdentity {
            package_name: "shared".into(),
            package_version: version.into(),
            manifest_dir: Some(source.into()),
            ..Default::default()
        };
        let metadata = |version: &str, source: &str| {
            canonical_rustc_unit_metadata(
                &arguments,
                OsStr::new("/workspace"),
                &unit(version, source),
            )
        };

        assert_ne!(
            metadata("1.0.0", "/cargo/registry/src/index/shared-1.0.0"),
            metadata("2.0.0", "/cargo/registry/src/index/shared-2.0.0"),
        );
        assert_ne!(
            metadata("1.0.0", "/cargo/registry/src/index-a/shared-1.0.0"),
            metadata("1.0.0", "/cargo/registry/src/index-b/shared-1.0.0"),
        );
        assert_ne!(
            metadata("1.0.0", "/workspace/one/shared"),
            metadata("1.0.0", "/workspace/two/shared"),
        );
    }

    #[test]
    fn project_output_uses_the_cargo_target_name() {
        assert_eq!(
            actor_names_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"
                "#,
            )
            .unwrap(),
            ("private-age".into(), "private_age".into())
        );
        assert_eq!(
            actor_names_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"
                    [lib]
                    name = "age_claim"
                "#,
            )
            .unwrap(),
            ("private-age".into(), "age_claim".into())
        );
        assert!(actor_names_from_manifest("[workspace]").is_err());
    }

    #[test]
    fn workspace_member_builds_from_the_actor_workspace_root() {
        let member = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/actors/counter");
        let root = actor_build_root(&member).unwrap();
        assert_eq!(
            root.file_name().and_then(|name| name.to_str()),
            Some("actors")
        );
        assert_eq!(
            root.join("target/riscv64em-javm/release/v2_counter.elf"),
            root.join("target/riscv64em-javm/release")
                .join(format!("{}.elf", "v2-counter".replace('-', "_")))
        );
    }

    #[test]
    fn repeated_builds_emit_one_identical_actor_pvm_and_package() {
        use vos::metadata::{ActorMeta, MessageMeta};

        const META: ActorMeta = ActorMeta {
            actor_name: "deterministic-counter",
            messages: &[MessageMeta {
                name: "value",
                is_query: true,
                fields: &[],
                returns: "u64",
                doc: "",
                timeout_ms: 0,
                mode: 0,
                attested: false,
                space_role: None,
                actor_role: None,
            }],
            constructor: &[],
            kind: 0,
            caps: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
            provable: false,
        };

        let temp = TempDir::new("deterministic");
        let actor_pvm = grey_transpiler::assembler::Assembler::new().build();
        let (metadata, metadata_len) = vos::metadata::encode::<512>(&META);
        std::fs::write(temp.0.join("actor.pvm"), &actor_pvm).unwrap();
        std::fs::write(temp.0.join("actor.meta"), &metadata[..metadata_len]).unwrap();
        let build_args = |out_dir| Args {
            program: temp.0.join("actor.pvm"),
            name: None,
            version: "2.0.0".into(),
            out_dir,
            interfaces: None,
            role_policies: None,
            schemas: Some(temp.0.join("actor.meta")),
            source_map: None,
            tasks: vec![],
            include_elf: false,
            crdt: false,
        };
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        let signer = libp2p::identity::Keypair::generate_ed25519();

        run_with_signer(build_args(first.clone()), &signer).unwrap();
        run_with_signer(build_args(second.clone()), &signer).unwrap();

        assert_eq!(
            std::fs::read(first.join("deterministic-counter.pvm")).unwrap(),
            actor_pvm,
        );
        assert_eq!(
            std::fs::read(first.join("deterministic-counter.pvm")).unwrap(),
            std::fs::read(second.join("deterministic-counter.pvm")).unwrap(),
        );
        assert_eq!(
            std::fs::read(first.join("deterministic-counter.vos")).unwrap(),
            std::fs::read(second.join("deterministic-counter.vos")).unwrap(),
        );
        assert!(!first.join("deterministic-counter.attestation.pvm").exists());
        assert_eq!(std::fs::read_dir(first).unwrap().count(), 2);
    }
}
