//! `space export` — query a space's registry and dump a
//! round-trippable TOML recipe.
//!
//! Connects to the running daemon via `DaemonClient`, calls
//! `programs()` / `agents()` / `members()` over libp2p, and
//! formats the result as TOML to stdout. Same model as every
//! other `space *` command — the daemon is the source of truth.

use vos::registry::{AgentRow, MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberRow, ProgramRow};

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::consistency_name;
use crate::spaces_index::SpaceEntry;

pub struct Args {
    pub query: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.query, |client| {
        let programs = client.programs()?;
        let agents = client.agents()?;
        let members = client.members()?;
        print_recipe(&client.entry, &programs, &agents, &members);
        Ok(())
    })
}

fn print_recipe(
    entry: &SpaceEntry,
    programs: &[ProgramRow],
    agents: &[AgentRow],
    members: &[MemberRow],
) {
    println!("# vosx space export — round-trippable recipe");
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
        println!(
            "program        = {:?}",
            format!("{}:{}", a.program_name, a.program_version)
        );
        println!("program_hash   = {:?}", hex::encode(a.program_hash));
        println!("replication_id = {:?}", hex::encode(a.replication_id));
        println!("consistency    = {:?}", consistency_name(a.consistency));
        // Serving-side sync floor — round-trips through `apply` so
        // re-importing preserves who this replica's state is served to.
        println!("sync           = {:?}", a.sync_role.as_str());
        // Only emitted when opted in — confined is the default, so a re-import
        // of an omitted field correctly defaults back to false.
        if a.network_reachable {
            println!("network_reachable = true");
        }
        println!();
    }

    // Members are informational (the reconciler ignores them — nodes
    // and identities are managed with `space members`). Emit them as an
    // array-of-tables so the output stays valid TOML: a `[members]`
    // table with two `node = …` keys is a duplicate-key parse error, so
    // `export | apply` would fail on any space with ≥2 members.
    for m in members {
        match m.kind {
            MEMBER_KIND_NODE => {
                println!("[[member]]");
                println!("kind    = \"node\"");
                println!("prefix  = {}", m.prefix);
                println!("peer_id = {:?}", hex::encode(&m.key));
                println!("role    = {}", m.role);
                println!();
            }
            MEMBER_KIND_IDENTITY => {
                println!("[[member]]");
                println!("kind       = \"identity\"");
                println!("public_key = {:?}", hex::encode(&m.key));
                println!("proof_kind = {}", m.proof_kind);
                println!();
            }
            other => {
                println!("# unknown member kind {other}");
            }
        }
    }
}
