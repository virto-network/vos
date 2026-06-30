//! `space upgrade` — repoint an agent at a different program version.

use serde::Serialize;
use space_registry::{Status};

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_ref;
use crate::output;

#[derive(Serialize)]
struct UpgradedView<'a> {
    instance_name: &'a str,
    program_name: &'a str,
    program_version: &'a str,
    program_hash: String,
}

pub struct Args {
    pub space: String,
    pub instance: String,
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (program_name, program_version) = parse_program_ref(&args.program_ref)?;

    DaemonClient::with_connect(&args.space, |client| {
        let program = client
            .program(&program_name, &program_version)?
            .ok_or_else(|| {
                anyhow::anyhow!("program {program_name}:{program_version} not in catalog",)
            })?;

        let status = client.upgrade(
            args.instance.clone(),
            program_name.clone(),
            program_version.clone(),
            program.hash.to_vec(),
        )?;

        match status {
            Status::Ok => {
                if output::is_json() {
                    output::print_json(&UpgradedView {
                        instance_name: &args.instance,
                        program_name: &program_name,
                        program_version: &program_version,
                        program_hash: hex::encode(program.hash),
                    });
                } else {
                    println!(
                        "upgraded {} → {program_name}:{program_version}",
                        args.instance,
                    );
                }
                Ok(())
            }
            Status::NotFound => anyhow::bail!("no agent named '{}' installed", args.instance),
            Status::ProgramNotFound => {
                anyhow::bail!("program {program_name}:{program_version} not in catalog")
            }
            other => anyhow::bail!("upgrade returned status {other}"),
        }
    })
}
