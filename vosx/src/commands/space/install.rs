//! `space install` — instantiate a published program as an
//! installed agent.

use serde::Serialize;
use vos::registry::{ProgramKind, Status};

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{
    auto_replication_id, parse_consistency, parse_instance_name, parse_nonzero_replication_id,
    parse_program_name,
};
use crate::output;

#[derive(Serialize)]
struct InstalledView<'a> {
    instance_name: &'a str,
    program_name: &'a str,
    program_hash: String,
    replication_id: String,
    consistency: &'a str,
}

pub struct Args {
    pub space: String,
    /// Published program name.
    pub program_ref: String,
    /// Override the install/instance name. Defaults to the
    /// program's name.
    pub name: Option<String>,
    /// Consistency mode: local, crdt, or raft.
    pub consistency: String,
    /// Optional explicit replication id (64 hex). Defaults to
    /// auto-derived from instance_name + program_hash.
    pub replication_id: Option<String>,
    /// Serving-side sync floor: `public` | `member` | `private`.
    /// Defaults to `member`.
    pub sync: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let program_name = parse_program_name(&args.program_ref)?;
    let instance_name = parse_instance_name(args.name.as_deref().unwrap_or(&program_name))?;

    let consistency = parse_consistency(&args.consistency).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown consistency '{}', expected local|crdt|raft",
            args.consistency,
        )
    })?;
    if consistency == vos::node::Consistency::Ephemeral as u8 {
        anyhow::bail!("service packages require local, crdt, or raft consistency");
    }

    let sync_role = vos::registry::SyncFloor::parse(&args.sync).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown sync floor '{}', expected public|member|private",
            args.sync,
        )
    })?;
    let explicit_replication_id = args
        .replication_id
        .as_deref()
        .map(parse_nonzero_replication_id)
        .transpose()
        .map_err(|error| anyhow::anyhow!("--replication-id: {error}"))?;

    DaemonClient::with_connect(&args.space, |client| {
        let program = client
            .program(&program_name)?
            .ok_or_else(|| anyhow::anyhow!("program {program_name} is not published"))?;
        if !matches!(&program.kind, ProgramKind::Service { .. }) {
            anyhow::bail!(
                "program {program_name} is an AgentActor package; `space install` only installs service actors"
            );
        }

        let replication_id = match explicit_replication_id {
            Some(value) => value,
            None => {
                let space_id = client
                    .entry
                    .id_bytes()
                    .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
                auto_replication_id(&space_id, &instance_name, &program.hash)
            }
        };

        let installation_id = super::common::mint_installation_id()?;
        let status = client.install_service_actor(
            instance_name.clone(),
            program_name.clone(),
            program.tag(),
            installation_id,
            replication_id,
            consistency,
            false, // network_reachable — CLI installs stay confined by default
            sync_role,
        )?;

        match status {
            Status::Ok => {
                if output::is_json() {
                    output::print_json(&InstalledView {
                        instance_name: &instance_name,
                        program_name: &program_name,
                        program_hash: hex::encode(program.hash),
                        replication_id: hex::encode(replication_id),
                        consistency: &args.consistency,
                    });
                } else {
                    println!("installed {instance_name}");
                    println!("  program        = {program_name}");
                    println!("  program_hash   = {}", hex::encode(program.hash));
                    println!("  replication_id = {}", hex::encode(replication_id));
                    println!("  consistency    = {}", args.consistency);
                }
                Ok(())
            }
            Status::InstanceExists => anyhow::bail!(
                "an agent named '{instance_name}' is already installed; pass --name to disambiguate",
            ),
            Status::ProgramNotFound => {
                anyhow::bail!("program {program_name} is no longer published")
            }
            Status::ConsistencyWidenDenied => anyhow::bail!(
                "'{instance_name}' was previously installed at a more confined consistency tier; \
                 a name's locality may only narrow, never widen. Use a fresh --name to install at \
                 '{}'.",
                args.consistency,
            ),
            Status::CrdtOptInRequired => anyhow::bail!(
                "'{instance_name}' cannot use CRDT consistency: its program was not built with \
                 #[actor(crdt)]. Choose local/raft, or declare CRDT fields explicitly and rebuild.",
            ),
            other => anyhow::bail!("install returned status {other}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_rejects_noncanonical_instance_before_connecting() {
        let error = run(Args {
            space: "does-not-exist".into(),
            program_ref: "worker-program".into(),
            name: Some("Bad_Instance".into()),
            consistency: "local".into(),
            replication_id: None,
            sync: "member".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("instance name"), "{error}");
        assert!(error.contains("canonical registry slug"), "{error}");
    }

    #[test]
    fn install_rejects_off_and_zero_replication_ids_before_connecting() {
        for replication_id in ["off".to_string(), "00".repeat(32)] {
            let error = run(Args {
                space: "does-not-exist".into(),
                program_ref: "worker-program".into(),
                name: Some("worker".into()),
                consistency: "local".into(),
                replication_id: Some(replication_id),
                sync: "member".into(),
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains("--replication-id"), "{error}");
            assert!(
                error.contains("not supported") || error.contains("nonzero"),
                "{error}"
            );
        }
    }
}
