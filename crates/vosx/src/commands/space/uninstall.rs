//! `space uninstall` — tombstone an agent.

use space_registry::{STATUS_NOT_FOUND, STATUS_OK};

use crate::commands::space::client::DaemonClient;

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        match client.uninstall(instance.to_string())? {
            STATUS_OK => {
                // The redb file under `<data_dir>/agents/<svc_id>.redb`
                // is held open by the running daemon and can't be
                // moved here. The next `space up` sweeps orphan
                // redbs into `<data_dir>/trash/` (see
                // `up::sweep_orphan_redbs`).
                println!("uninstalled {instance}");
                Ok(())
            }
            STATUS_NOT_FOUND => anyhow::bail!("no agent named '{instance}' installed"),
            other => anyhow::bail!("uninstall returned status {other}"),
        }
    })
}
