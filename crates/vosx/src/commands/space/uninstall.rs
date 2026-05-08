//! `space uninstall` — tombstone an agent.

use space_registry::{STATUS_NOT_FOUND, STATUS_OK};

use crate::commands::space::client::DaemonClient;

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        match client.uninstall(instance.to_string())? {
            STATUS_OK => {
                println!("uninstalled {instance}");
                Ok(())
            }
            STATUS_NOT_FOUND => anyhow::bail!("no agent named '{instance}' installed"),
            other => anyhow::bail!("uninstall returned status {other}"),
        }
        // TODO: move per-agent redb to space_dir/trash/{instance}
        // so an `--undo` can recover instead of leaving the file
        // orphaned.
    })
}
