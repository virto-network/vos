//! `space uninstall` — tombstone an agent.

use space_registry::{STATUS_NOT_FOUND, STATUS_OK};

use crate::commands::space::client::DaemonClient;

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    let client = DaemonClient::connect(space)?;
    let reg = client.registry();

    let status = vos::block_on(reg.uninstall(
        &mut &*client.node(),
        instance.to_string(),
    ))
    .map_err(|e| anyhow::anyhow!("uninstall() failed: {e}"))?;

    match status {
        STATUS_OK => println!("uninstalled {instance}"),
        STATUS_NOT_FOUND => anyhow::bail!("no agent named '{instance}' installed"),
        other => anyhow::bail!("uninstall returned status {other}"),
    }

    // TODO(phase 4): move per-agent redb to space_dir/trash/{instance}
    //   so the data is recoverable instead of left dangling.

    client.shutdown()
}
