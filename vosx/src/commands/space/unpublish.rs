//! `space unpublish` — remove a program from the catalog.

use serde::Serialize;
use vos::registry::Status;

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct UnpublishedView<'a> {
    name: &'a str,
}

pub struct Args {
    pub space: String,
    /// Catalog name.
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let name = super::common::parse_program_name(&args.program_ref)?;

    DaemonClient::with_connect(&args.space, |client| {
        match client.unpublish(name.clone())? {
            Status::Ok => {
                if output::is_json() {
                    output::print_json(&UnpublishedView { name: &name });
                } else {
                    println!("unpublished {name}");
                }
                Ok(())
            }
            Status::NotFound => anyhow::bail!("{name} is not published"),
            Status::InUse => {
                anyhow::bail!("{name} is referenced by an installed actor — uninstall first")
            }
            other => anyhow::bail!("unpublish returned status {other}"),
        }
    })
}
