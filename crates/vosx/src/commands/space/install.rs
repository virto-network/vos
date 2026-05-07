//! `space install` — instantiate a published program as an
//! installed agent.

use vos::init::{InitArgs, InitValue};
use space_registry::{
    auto_replication_id, parse_consistency, STATUS_INSTANCE_EXISTS,
    STATUS_OK, STATUS_PROGRAM_NOT_FOUND,
};

use crate::commands::space::client::DaemonClient;

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

    let init_args = parse_init_args(&args.init)?;
    let install_args = if init_args_is_empty(&init_args) {
        Vec::new()
    } else {
        vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&init_args)
            .map_err(|e| anyhow::anyhow!("encode init args: {e}"))?
            .to_vec()
    };

    let client = DaemonClient::connect(&args.space)?;
    let reg = client.registry();

    // Look up the program so we know its hash to pin against.
    let program = vos::block_on(reg.program(
        &mut &*client.node(),
        program_name.clone(),
        program_version.clone(),
    ))
    .map_err(|e| anyhow::anyhow!("program() failed: {e}"))?
    .ok_or_else(|| {
        anyhow::anyhow!("program {program_name}:{program_version} not in catalog. publish it first.")
    })?;

    let replication_id = match &args.replication_id {
        Some(hex) => crate::blob_store::BlobHash::from_hex(hex)
            .map_err(|_| anyhow::anyhow!("--replication-id must be 64 hex"))?
            .0,
        None => auto_replication_id(&instance_name, &program.hash),
    };

    let status = vos::block_on(reg.install(
        &mut &*client.node(),
        instance_name.clone(),
        program_name.clone(),
        program_version.clone(),
        program.hash.to_vec(),
        replication_id.to_vec(),
        consistency,
        install_args,
    ))
    .map_err(|e| anyhow::anyhow!("install() failed: {e}"))?;

    match status {
        STATUS_OK => {
            println!("installed {instance_name}");
            println!("  program        = {program_name}:{program_version}");
            println!("  program_hash   = {}", hex::encode(program.hash));
            println!("  replication_id = {}", hex::encode(replication_id));
            println!("  consistency    = {}", args.consistency);
        }
        STATUS_INSTANCE_EXISTS => anyhow::bail!(
            "an agent named '{instance_name}' is already installed; pass --name to disambiguate",
        ),
        STATUS_PROGRAM_NOT_FOUND => anyhow::bail!(
            "program {program_name}:{program_version} not in catalog (race?)",
        ),
        other => anyhow::bail!("install returned status {other}"),
    }

    client.shutdown()
}

fn parse_program_ref(s: &str) -> anyhow::Result<(String, String)> {
    if let Some((n, v)) = s.split_once(':') {
        if n.is_empty() || v.is_empty() {
            anyhow::bail!("program ref '{s}' must be 'name' or 'name:version'");
        }
        Ok((n.to_string(), v.to_string()))
    } else {
        Ok((s.to_string(), "latest".to_string()))
    }
}

fn parse_init_args(pairs: &[String]) -> anyhow::Result<InitArgs> {
    let mut args = InitArgs::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--init expects key=value, got '{pair}'"))?;
        // Try numeric first so `--init n=42` types as u64; fall
        // back to string. The InitValue carrying string is fine
        // for actors whose `new()` takes a `String`, and the
        // numeric path covers the common counter/size cases.
        if let Ok(n) = v.parse::<u64>() {
            args = args.with(k, InitValue::U64(n));
        } else if let Ok(b) = v.parse::<bool>() {
            args = args.with(k, InitValue::Bool(b));
        } else {
            args = args.with(k, InitValue::Str(v.to_string()));
        }
    }
    Ok(args)
}

/// `InitArgs` doesn't expose `is_empty()` and we don't want to
/// reach into its internals — sniff via the encoded length
/// instead. An empty InitArgs serializes to a fixed marker
/// shorter than ~10 bytes.
fn init_args_is_empty(args: &InitArgs) -> bool {
    let bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(args)
        .map(|av| av.to_vec())
        .unwrap_or_default();
    let empty_bytes = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&InitArgs::new())
        .map(|av| av.to_vec())
        .unwrap_or_default();
    bytes == empty_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_init_typed_numbers_first() {
        let args = parse_init_args(&["n=42".into(), "ok=true".into(), "s=hello".into()]).unwrap();
        // Just verify we can re-encode without panicking; the
        // typed dispatch is exercised inside `with`.
        assert!(!init_args_is_empty(&args));
    }

    #[test]
    fn empty_init_returns_empty() {
        let args = parse_init_args(&[]).unwrap();
        assert!(init_args_is_empty(&args));
    }
}
