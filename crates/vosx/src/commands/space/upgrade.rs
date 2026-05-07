//! `space upgrade` — repoint an agent at a different program version.

use vos::abi::service::ServiceId;
use space_registry::{
    SpaceRegistryRef, STATUS_NOT_FOUND, STATUS_OK, STATUS_PROGRAM_NOT_FOUND,
};

use crate::commands::space::transient::TransientRegistry;

pub struct Args {
    pub space: String,
    pub instance: String,
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (program_name, program_version) = parse_program_ref(&args.program_ref)?;

    let reg_handle = TransientRegistry::boot(&args.space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);

    let program = vos::block_on(reg.program(
        &mut &*reg_handle.node(),
        program_name.clone(),
        program_version.clone(),
    ))
    .map_err(|e| anyhow::anyhow!("program() failed: {e}"))?
    .ok_or_else(|| anyhow::anyhow!("program {program_name}:{program_version} not in catalog"))?;

    let status = vos::block_on(reg.upgrade(
        &mut &*reg_handle.node(),
        args.instance.clone(),
        program_name.clone(),
        program_version.clone(),
        program.hash.to_vec(),
    ))
    .map_err(|e| anyhow::anyhow!("upgrade() failed: {e}"))?;

    match status {
        STATUS_OK => println!(
            "upgraded {} → {program_name}:{program_version}",
            args.instance,
        ),
        STATUS_NOT_FOUND => anyhow::bail!("no agent named '{}' installed", args.instance),
        STATUS_PROGRAM_NOT_FOUND => {
            anyhow::bail!("program {program_name}:{program_version} not in catalog")
        }
        other => anyhow::bail!("upgrade returned status {other}"),
    }

    reg_handle.shutdown()
}

fn parse_program_ref(s: &str) -> anyhow::Result<(String, String)> {
    if let Some((n, v)) = s.split_once(':') {
        if n.is_empty() || v.is_empty() {
            anyhow::bail!("program ref '{s}' must be 'name' or 'name:version'");
        }
        Ok((n.to_string(), v.to_string()))
    } else {
        Ok((s.to_string(), "latest".to_string()))
    }
}
