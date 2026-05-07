//! `space export` — query a space's registry and dump a
//! round-trippable TOML manifest.
//!
//! Boots the registry briefly (read-only intent — we don't
//! mutate state), invokes `programs()` / `agents()` /
//! `members()` via the macro-generated `SpaceRegistryRef`, and
//! formats the result as TOML to stdout.

use std::path::PathBuf;

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};
use space_registry::{
    consistency_name, AgentRow, MemberRow, ProgramRow, SpaceRegistryRef,
    MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE,
};

use crate::blob_store::{self, BlobHash};
use crate::commands::space::up::derive_registry_replication_id;
use crate::spaces_index;

pub struct Args {
    pub query: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.query)?;

    if entry.registry_hash.is_empty() {
        anyhow::bail!("space '{}' missing registry_hash", entry.name);
    }
    let hash = BlobHash::from_hex(&entry.registry_hash)
        .map_err(|_| anyhow::anyhow!("registry_hash not valid hex"))?;
    let elf = blob_store::cache_get(&hash)?
        .ok_or_else(|| anyhow::anyhow!("registry blob {hash} not in cache"))?;
    let blob = grey_transpiler::link_elf(&elf)
        .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;
    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id is not 32 bytes of hex"))?;

    let data_dir = PathBuf::from(&entry.data_dir);

    let mut node = VosNode::new();
    let cfg = AgentConfig::new(blob)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(derive_registry_replication_id(&space_id))
        .persist(&data_dir);
    let _id = node.register_at_id(cfg, ServiceId::REGISTRY);

    // Query via the macro-generated Ref. Block on each call;
    // they're synchronous from the host's perspective.
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let programs = vos::block_on(reg.programs(&mut &node))
        .map_err(|e| anyhow::anyhow!("programs() failed: {e}"))?;
    let agents = vos::block_on(reg.agents(&mut &node))
        .map_err(|e| anyhow::anyhow!("agents() failed: {e}"))?;
    let members = vos::block_on(reg.members(&mut &node))
        .map_err(|e| anyhow::anyhow!("members() failed: {e}"))?;

    print_manifest(entry, &programs, &agents, &members);

    node.shutdown();
    let _ = node.collect();
    Ok(())
}

fn print_manifest(
    entry: &spaces_index::SpaceEntry,
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
