//! `space install` — instantiate a published program as an
//! installed agent.

use serde::Serialize;
use vos::registry::Status;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{auto_replication_id, parse_consistency, parse_program_ref};
use crate::output;

#[derive(Serialize)]
struct InstalledView<'a> {
    instance_name: &'a str,
    program_name: &'a str,
    program_version: &'a str,
    program_hash: String,
    replication_id: String,
    consistency: &'a str,
}

pub struct Args {
    pub space: String,
    /// Program ref: `name`, `name:version`, or `name:version@hash`.
    /// Bare `name` resolves to `name:latest`.
    pub program_ref: String,
    /// Override the install/instance name. Defaults to the
    /// program's name.
    pub name: Option<String>,
    /// Consistency mode: ephemeral, local, crdt, or raft.
    pub consistency: String,
    /// Optional explicit replication id (64 hex). Defaults to
    /// auto-derived from instance_name + program_hash.
    pub replication_id: Option<String>,
    /// Serving-side sync floor: `public` | `member` | `private`.
    /// Defaults to `member`.
    pub sync: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (program_name, program_version) = parse_program_ref(&args.program_ref)?;
    let instance_name = args.name.unwrap_or_else(|| program_name.clone());

    let consistency = parse_consistency(&args.consistency).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown consistency '{}', expected ephemeral|local|crdt|raft",
            args.consistency,
        )
    })?;

    let sync_role = vos::registry::SyncFloor::parse(&args.sync).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown sync floor '{}', expected public|member|private",
            args.sync,
        )
    })?;

    DaemonClient::with_connect(&args.space, |client| {
        let program = client
            .program(&program_name, &program_version)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "program {program_name}:{program_version} not in catalog. publish it first.",
                )
            })?;

        let replication_id = match &args.replication_id {
            Some(hex) => {
                crate::blob_store::BlobHash::from_hex(hex)
                    .map_err(|_| anyhow::anyhow!("--replication-id must be 64 hex"))?
                    .0
            }
            None => {
                let space_id = client
                    .entry
                    .id_bytes()
                    .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
                auto_replication_id(&space_id, &instance_name, &program.hash)
            }
        };

        let status = client.install(
            instance_name.clone(),
            program_name.clone(),
            program_version.clone(),
            program.hash.to_vec(),
            replication_id.to_vec(),
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
                        program_version: &program_version,
                        program_hash: hex::encode(program.hash),
                        replication_id: hex::encode(replication_id),
                        consistency: &args.consistency,
                    });
                } else {
                    println!("installed {instance_name}");
                    println!("  program        = {program_name}:{program_version}");
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
                anyhow::bail!("program {program_name}:{program_version} not in catalog (race?)",)
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
