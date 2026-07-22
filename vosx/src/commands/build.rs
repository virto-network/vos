//! Build a canonical actor PVM and its signed `.vos` v2 package.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use vos::v2::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageManifestV2, PackageRolePoliciesV2,
    ProducerId, ProgramId, ServicePvmV2, V2Wire, VosPackageV2, artifact_hash,
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
    pub external_actors: Vec<String>,
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
    let mut external_actors = args.external_actors;
    if external_actors.iter().any(String::is_empty) {
        bail!("--external-actor names must not be empty");
    }
    external_actors.sort();
    if external_actors.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("--external-actor names must be unique");
    }

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
            external_actors,
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
    let (package_name, actor_target_name) = actor_names_from_manifest(&manifest)?;
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
        .join(format!("{actor_target_name}.elf"));
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

fn service_program_id(bytes: &[u8]) -> anyhow::Result<ProgramId> {
    let program = ProgramId::of_pvm(bytes);
    ServicePvmV2::new(bytes.to_vec(), program).map_err(|error| {
        anyhow!(
            "--service-pvm must contain the canonical generic service with valid JAM Refine/Accumulate entries: {error}"
        )
    })?;
    Ok(program)
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

    fn service_pvm() -> Vec<u8> {
        use grey_transpiler::assembler::Reg;

        fn emit(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, bytes: &[u8]) {
            code.extend_from_slice(bytes);
            bitmask.push(1);
            bitmask.resize(code.len(), 0);
        }

        fn halt(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
            let mut load = vec![20, Reg::T0 as u8];
            load.extend_from_slice(&(javm::PVM_HALT_ADDR as u64).to_le_bytes());
            emit(code, bitmask, &load);
            let mut jump = vec![50, Reg::T0 as u8];
            jump.extend_from_slice(&0u32.to_le_bytes());
            emit(code, bitmask, &jump);
        }

        let mut code = vec![40, 0, 0, 0, 0, 40, 0, 0, 0, 0];
        let mut bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let refine_body = code.len();
        halt(&mut code, &mut bitmask);
        let accumulate_body = code.len();
        halt(&mut code, &mut bitmask);
        code[1..5].copy_from_slice(&(refine_body as i32).to_le_bytes());
        code[6..10].copy_from_slice(&((accumulate_body as i32) - 5).to_le_bytes());
        grey_transpiler::emitter::build_service_program_with_args_pages(
            &code,
            &bitmask,
            &[],
            &[],
            &[],
            1,
            0,
            4,
            vos::v2::SERVICE_ARGUMENT_PAGES_V2,
        )
    }

    fn build_args(root: &Path, out_dir: PathBuf) -> Args {
        Args {
            program: root.join("actor.pvm"),
            name: None,
            version: "2.0.0".into(),
            out_dir,
            service_pvm: root.join("vos-service.pvm"),
            interfaces: None,
            role_policies: None,
            schemas: Some(root.join("actor.meta")),
            source_map: None,
            include_elf: false,
            crdt: false,
            external_actors: Vec::new(),
        }
    }

    #[test]
    fn service_program_rejects_actor_only_and_malformed_pvms() {
        let mut assembler = grey_transpiler::assembler::Assembler::new();
        assembler
            .load_imm_64(grey_transpiler::assembler::Reg::A0, 0)
            .ecalli(0);
        assert!(service_program_id(&assembler.build()).is_err());
        assert!(service_program_id(&[]).is_err());
        assert!(service_program_id(b"not a JAR program").is_err());
    }

    #[test]
    fn project_output_uses_the_cargo_target_name() {
        assert_eq!(
            actor_names_from_manifest(
                r#"
                    [package]
                    name = "private-age"
                    version = "0.1.0"

                    [lib]
                    name = "private_age_actor"
                "#,
            )
            .unwrap(),
            ("private-age".into(), "private_age_actor".into())
        );
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
            }],
            constructor: &[],
            kind: 0,
            caps: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
        };

        let temp = TempDir::new("deterministic");
        let actor_pvm = grey_transpiler::assembler::Assembler::new().build();
        let (metadata, metadata_len) = vos::metadata::encode::<512>(&META);
        std::fs::write(temp.0.join("actor.pvm"), &actor_pvm).unwrap();
        std::fs::write(temp.0.join("actor.meta"), &metadata[..metadata_len]).unwrap();
        std::fs::write(temp.0.join("vos-service.pvm"), service_pvm()).unwrap();

        let first = temp.0.join("first");
        let second = temp.0.join("second");
        let signer = libp2p::identity::Keypair::generate_ed25519();
        run_with_signer(build_args(&temp.0, first.clone()), &signer).unwrap();
        run_with_signer(build_args(&temp.0, second.clone()), &signer).unwrap();

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
