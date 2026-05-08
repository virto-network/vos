//! `space unpublish` — remove a program from the catalog.

use space_registry::{STATUS_IN_USE, STATUS_NOT_FOUND, STATUS_OK};

use crate::commands::space::client::DaemonClient;

pub struct Args {
    pub space: String,
    /// `name:version` — both halves required (you'd typically
    /// not want to drop ALL versions of a name in one call).
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (n, v) = args.program_ref.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "unpublish requires both name and version: 'name:version', got '{}'",
            args.program_ref,
        )
    })?;
    if n.is_empty() || v.is_empty() {
        anyhow::bail!("name and version must both be non-empty");
    }
    let (n, v) = (n.to_string(), v.to_string());

    DaemonClient::with_connect(&args.space, |client| {
        match client.unpublish(n.clone(), v.clone())? {
            STATUS_OK => {
                println!("unpublished {n}:{v}");
                Ok(())
            }
            STATUS_NOT_FOUND => anyhow::bail!("{n}:{v} not in catalog"),
            STATUS_IN_USE => anyhow::bail!(
                "{n}:{v} is referenced by an installed agent — uninstall first",
            ),
            other => anyhow::bail!("unpublish returned status {other}"),
        }
    })
}
