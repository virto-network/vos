//! `space install` — instantiate a published program as an
//! installed agent.

use serde::Serialize;
use space_registry::{Status};
use vos::init::{InitArgs, InitValue};

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
    /// `key=value` init args. Values are typed by the actor's
    /// constructor signature, but we accept strings here and
    /// let `InitValue::String` carry — actors that expect
    /// numeric init args can extend this CLI later.
    pub init: Vec<String>,
    /// Consistency mode: ephemeral, local, crdt, or raft.
    pub consistency: String,
    /// Optional explicit replication id (64 hex). Defaults to
    /// auto-derived from instance_name + program_hash.
    pub replication_id: Option<String>,
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

    let install_args = encode_init_args(&args.init)?;

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
            None => auto_replication_id(&instance_name, &program.hash),
        };

        let status = client.install(
            instance_name.clone(),
            program_name.clone(),
            program_version.clone(),
            program.hash.to_vec(),
            replication_id.to_vec(),
            consistency,
            install_args,
            Vec::new(), // install_payloads — CLI install has no on_start
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
            other => anyhow::bail!("install returned status {other}"),
        }
    })
}

/// Build the rkyv-encoded `install_args` blob from a list of
/// `key=value` strings. Empty input returns empty bytes — the
/// registry treats empty `install_args` as "no init args" and
/// the daemon skips populating `INIT_KEY` storage.
fn encode_init_args(pairs: &[String]) -> anyhow::Result<Vec<u8>> {
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = InitArgs::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--init expects key=value, got '{pair}'"))?;
        // Try numeric first so `--init n=42` types as u64; fall
        // back to string. InitValue carrying a string is fine
        // for actors whose `new()` takes a `String`; the numeric
        // path covers the common counter/size cases.
        if let Ok(n) = v.parse::<u64>() {
            args = args.with(k, InitValue::U64(n));
        } else if let Ok(b) = v.parse::<bool>() {
            args = args.with(k, InitValue::Bool(b));
        } else {
            args = args.with(k, InitValue::Str(v.to_string()));
        }
    }
    Ok(vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&args)
        .map_err(|e| anyhow::anyhow!("encode init args: {e}"))?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_init_returns_empty() {
        assert!(encode_init_args(&[]).unwrap().is_empty());
    }

    #[test]
    fn nonempty_init_returns_nonempty() {
        let bytes = encode_init_args(&["n=42".into(), "ok=true".into(), "s=hello".into()]).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn rejects_pairs_without_eq() {
        assert!(encode_init_args(&["bare".into()]).is_err());
    }
}
