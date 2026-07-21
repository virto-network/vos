//! Build a canonical actor PVM and its signed `.vos` v2 package.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use vos::v2::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageManifestV2, PackageRolePoliciesV2,
    ProducerId, ProgramId, V2Wire, VosPackageV2, artifact_hash,
};

pub struct Args {
    pub program: PathBuf,
    pub name: Option<String>,
    pub version: String,
    pub out_dir: PathBuf,
    pub service_pvm: PathBuf,
    pub interfaces: Option<PathBuf>,
    pub role_policies: Option<PathBuf>,
    pub schemas: Option<PathBuf>,
    pub source_map: Option<PathBuf>,
    pub include_elf: bool,
    pub crdt: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
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
    javm::program::parse_blob(&actor_pvm).ok_or_else(|| anyhow!("invalid canonical actor PVM"))?;

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
    let generated_role_policies = PackageRolePoliciesV2::from_metadata(&actor_metadata)?.encode();
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
    let service_pvm = std::fs::read(&args.service_pvm)
        .with_context(|| format!("read pinned service PVM {}", args.service_pvm.display()))?;
    let service_program = service_program_id(&service_pvm)?;
    let actor_program = ProgramId::of_pvm(&actor_pvm);

    let keypair = crate::identity::load_or_create()?;
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
        },
        actor_pvm: actor_pvm.clone(),
        generated_interfaces: interfaces,
        role_policies,
        schemas,
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

fn resolve_program_input(input: &Path) -> anyhow::Result<PathBuf> {
    if !input.is_dir() {
        return Ok(input.to_path_buf());
    }
    let manifest_path = input.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read actor manifest {}", manifest_path.display()))?;
    let package_name = package_name_from_manifest(&manifest)?;
    let build_root = actor_build_root(input)?;
    let mut command = Command::new("cargo");
    command.args(["+nightly", "actor"]);
    if build_root != input {
        command.args(["-p", &package_name]);
    }
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
    let elf = build_root
        .join("target/riscv64em-javm/release")
        .join(format!("{}.elf", package_name.replace('-', "_")));
    if !elf.is_file() {
        bail!(
            "actor build succeeded but did not produce {}; ensure the project uses the VOS cargo actor configuration",
            elf.display()
        );
    }
    Ok(elf)
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

fn package_name_from_manifest(manifest: &str) -> anyhow::Result<String> {
    let manifest: toml::Value = manifest
        .parse()
        .map_err(|error| anyhow!("parse actor Cargo.toml: {error}"))?;
    manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("actor Cargo.toml needs a non-empty [package].name"))
}

fn read_optional(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    path.map(std::fs::read)
        .transpose()
        .map(|bytes| bytes.unwrap_or_default())
        .map_err(Into::into)
}

fn service_program_id(bytes: &[u8]) -> anyhow::Result<ProgramId> {
    if bytes.is_empty() || javm::program::parse_blob(bytes).is_none() {
        bail!("--service-pvm must contain one canonical JAR program")
    }
    Ok(ProgramId::of_pvm(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_program_is_derived_from_valid_canonical_bytes() {
        let mut assembler = grey_transpiler::assembler::Assembler::new();
        assembler
            .load_imm_64(grey_transpiler::assembler::Reg::A0, 0)
            .ecalli(0);
        let pvm = assembler.build();
        assert_eq!(service_program_id(&pvm).unwrap(), ProgramId::of_pvm(&pvm));
        assert!(service_program_id(&[]).is_err());
        assert!(service_program_id(b"not a JAR program").is_err());
    }

    #[test]
    fn project_output_uses_the_cargo_package_name() {
        assert_eq!(
            package_name_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"
                "#,
            )
            .unwrap(),
            "private-age"
        );
        assert!(package_name_from_manifest("[workspace]").is_err());
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
}
