//! `space upgrade` — move an actor to the package currently named in the catalog.

use serde::Serialize;
use vos::registry::Status;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_name;
use crate::output;

#[derive(Serialize)]
struct UpgradedView<'a> {
    instance_name: &'a str,
    program_name: &'a str,
    program_hash: String,
}

pub struct Args {
    pub space: String,
    pub instance: String,
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let program_name = parse_program_name(&args.program_ref)?;

    DaemonClient::with_connect(&args.space, |client| {
        let program = client
            .program(&program_name)?
            .ok_or_else(|| anyhow::anyhow!("program {program_name} is not published"))?;

        let status = client.upgrade(
            args.instance.clone(),
            program_name.clone(),
            program.hash.to_vec(),
        )?;

        match status {
            Status::Ok => {
                if output::is_json() {
                    output::print_json(&UpgradedView {
                        instance_name: &args.instance,
                        program_name: &program_name,
                        program_hash: hex::encode(program.hash),
                    });
                } else {
                    println!("upgraded {} → {program_name}", args.instance);
                }
                Ok(())
            }
            Status::NotFound => anyhow::bail!("no agent named '{}' installed", args.instance),
            Status::ProgramNotFound => {
                anyhow::bail!("program {program_name} is no longer published")
            }
            other => anyhow::bail!("upgrade returned status {other}"),
        }
    })
}
