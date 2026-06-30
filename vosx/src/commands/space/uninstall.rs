//! `space uninstall` — tombstone an agent.

use serde::Serialize;
use space_registry::{Status};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct UninstalledView<'a> {
    instance_name: &'a str,
}

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        match client.uninstall(instance.to_string())? {
            Status::Ok => {
                // The redb file under `<data_dir>/agents/<svc_id>.redb`
                // is held open by the running daemon and can't be
                // moved here. The next `space up` sweeps orphan
                // redbs into `<data_dir>/trash/` (see
                // `up::sweep_orphan_redbs`).
                if output::is_json() {
                    output::print_json(&UninstalledView {
                        instance_name: instance,
                    });
                } else {
                    println!("uninstalled {instance}");
                }
                Ok(())
            }
            Status::NotFound => anyhow::bail!("no agent named '{instance}' installed"),
            other => anyhow::bail!("uninstall returned status {other}"),
        }
    })
}
