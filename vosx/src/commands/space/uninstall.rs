//! `space uninstall` — tombstone an agent.

use serde::Serialize;
use vos::registry::Status;

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct UninstalledView<'a> {
    instance_name: &'a str,
}

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    let instance = super::common::parse_instance_name(instance)?;
    DaemonClient::with_connect(space, |client| {
        let installed = client
            .agent(&instance)?
            .ok_or_else(|| anyhow::anyhow!("no service actor named '{instance}' installed"))?;
        match client.uninstall_service_actor(
            instance.clone(),
            installed.installation_id,
            installed.revision,
            vos::registry::ProgramTag {
                publication_id: installed.program_publication_id,
                hash: installed.program_hash,
            },
        )? {
            Status::Ok => {
                // The redb file under `<data_dir>/agents/<svc_id>.redb`
                // is held open by the running daemon and can't be
                // moved here. The next `space up` sweeps orphan
                // redbs into `<data_dir>/trash/` (see
                // `up::sweep_orphan_redbs`).
                if output::is_json() {
                    output::print_json(&UninstalledView {
                        instance_name: &instance,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_rejects_noncanonical_instance_before_connecting() {
        let error = run("does-not-exist", "Bad_Instance")
            .unwrap_err()
            .to_string();
        assert!(error.contains("instance name"), "{error}");
        assert!(error.contains("canonical registry slug"), "{error}");
    }
}
