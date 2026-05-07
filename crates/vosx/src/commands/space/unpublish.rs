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

    let client = DaemonClient::connect(&args.space)?;
    let reg = client.registry();

    let status = vos::block_on(reg.unpublish(
        &mut &*client.node(),
        n.to_string(),
        v.to_string(),
    ))
    .map_err(|e| anyhow::anyhow!("unpublish() failed: {e}"))?;

    match status {
        STATUS_OK => println!("unpublished {n}:{v}"),
        STATUS_NOT_FOUND => anyhow::bail!("{n}:{v} not in catalog"),
        STATUS_IN_USE => anyhow::bail!(
            "{n}:{v} is referenced by an installed agent — uninstall first",
        ),
        other => anyhow::bail!("unpublish returned status {other}"),
    }

    client.shutdown()
}
