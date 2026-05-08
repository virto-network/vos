//! `space export` — query a space's registry and dump a
//! round-trippable TOML manifest.
//!
//! Connects to the running daemon via `DaemonClient`, calls
//! `programs()` / `agents()` / `members()` over libp2p, and
//! formats the result as TOML to stdout. Same model as every
//! other `space *` command — the daemon is the source of truth.

use space_registry::{
    consistency_name, AgentRow, MemberRow, ProgramRow, MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE,
};

use crate::commands::space::client::DaemonClient;
use crate::spaces_index::SpaceEntry;

pub struct Args {
    pub query: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.query, |client| {
        let programs = client.programs()?;
        let agents = client.agents()?;
        let members = client.members()?;
        print_manifest(&client.entry, &programs, &agents, &members);
        Ok(())
    })
}

fn print_manifest(
    entry: &SpaceEntry,
    programs: &[ProgramRow],
    agents: &[AgentRow],
    members: &[MemberRow],
) {
    println!("# vosx space export — round-trippable manifest");
    println!("space    = {:?}", entry.name);
    println!("space_id = {:?}", entry.id);
    println!();

    for p in programs {
        println!("[[program]]");
        println!("name    = {:?}", p.name);
        println!("version = {:?}", p.version);
        println!("hash    = {:?}", hex::encode(p.hash));
        println!();
    }

    for a in agents {
        println!("[[agent]]");
        println!("name           = {:?}", a.instance_name);
        println!("program        = {:?}", format!("{}:{}", a.program_name, a.program_version));
        println!("program_hash   = {:?}", hex::encode(a.program_hash));
        println!("replication_id = {:?}", hex::encode(a.replication_id));
        println!("consistency    = {:?}", consistency_name(a.consistency));
        println!();
    }

    if !members.is_empty() {
        println!("[members]");
        for m in members {
            match m.kind {
                MEMBER_KIND_NODE => {
                    println!(
                        "node = {{ prefix = {}, peer_id = {:?}, role = {} }}",
                        m.prefix,
                        hex::encode(&m.key),
                        m.role,
                    );
                }
                MEMBER_KIND_IDENTITY => {
                    println!(
                        "identity = {{ public_key = {:?}, proof_kind = {} }}",
                        hex::encode(&m.key),
                        m.proof_kind,
                    );
                }
                other => {
                    println!("# unknown member kind {other}");
                }
            }
        }
        println!();
    }
}
