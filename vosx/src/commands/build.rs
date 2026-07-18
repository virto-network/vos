//! Build a canonical actor PVM and its signed `.vos` v2 package.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use vos::v2::{
    DeploymentSignatureV2, PackageDiagnosticsV2, PackageManifestV2, ProducerId, ProgramId, V2Wire,
    VosPackageV2, artifact_hash,
};

pub struct Args {
    pub program: PathBuf,
    pub name: Option<String>,
    pub version: String,
    pub out_dir: PathBuf,
    pub service_program_id: String,
    pub interfaces: Option<PathBuf>,
    pub role_policies: Option<PathBuf>,
    pub schemas: Option<PathBuf>,
    pub source_map: Option<PathBuf>,
    pub include_elf: bool,
    pub crdt: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let input =
        std::fs::read(&args.program).with_context(|| format!("read {}", args.program.display()))?;
    let is_pvm = args.program.extension().and_then(|x| x.to_str()) == Some("pvm");
    let actor_pvm = if is_pvm {
        input.clone()
    } else {
        grey_transpiler::link_elf(&input)
            .map_err(|error| anyhow!("transpile {}: {error:?}", args.program.display()))?
    };
    if actor_pvm.is_empty() {
        bail!("{} produced an empty PVM", args.program.display());
    }
    javm::program::parse_blob(&actor_pvm)
        .ok_or_else(|| anyhow!("invalid canonical actor PVM"))?;

    let actor_metadata = (!is_pvm).then(|| vos::metadata::from_elf(&input)).flatten();
    if args.crdt && actor_metadata.as_ref().is_some_and(|meta| !meta.crdt) {
        bail!(
            "{} is an ordinary actor; use #[actor(crdt)] instead of forcing --crdt",
            args.program.display(),
        );
    }
    let crdt = actor_metadata.as_ref().is_some_and(|meta| meta.crdt) || args.crdt;
    let name = args
        .name
        .or_else(|| actor_metadata.as_ref().map(|meta| meta.actor_name.clone()))
        .or_else(|| {
            args.program
                .file_stem()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| anyhow!("--name is required for this path"))?;

    let interfaces = read_optional(args.interfaces.as_deref())?;
    let role_policies = read_optional(args.role_policies.as_deref())?;
    let schemas = match args.schemas.as_deref() {
        Some(path) => std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
        None if !is_pvm => vos::metadata::raw_section_from_elf(&input).unwrap_or_default(),
        None => Vec::new(),
    };
    let source_map = read_optional(args.source_map.as_deref())?;
    let service_program = ProgramId(parse_hash(&args.service_program_id)?);
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

fn read_optional(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    path.map(std::fs::read)
        .transpose()
        .map(|bytes| bytes.unwrap_or_default())
        .map_err(Into::into)
}

fn parse_hash(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|_| anyhow!("--service-program-id must be 64 hex characters"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("--service-program-id must be exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_program_id_is_exact() {
        assert_eq!(parse_hash(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(parse_hash("ab").is_err());
        assert!(parse_hash("zz").is_err());
    }
}
