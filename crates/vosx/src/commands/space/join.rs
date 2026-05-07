//! `space join` — register a remote space locally so
//! `space up` can dial its bootnodes and sync.
//!
//! Writes a spaces.toml entry and lays out the per-space data
//! dir. Sync itself happens when the user runs `space up`.
//! The registry blob comes from `--registry <source>`
//! (defaults to the bundled blob); peer-fetch over libp2p is
//! a future addition. `space_id` is taken on trust from the
//! bootstrap address — `space up` then verifies that the
//! genesis CrdtEvent in the synced registry derives back to
//! it (see `verify.rs`).

use std::path::PathBuf;

use crate::commands::space::new::resolve_registry_source;
use crate::paths;
use crate::spaces_index::{self, SpacesIndex};

pub struct Args {
    pub bootstrap: String,
    pub registry: Option<String>,
    pub name: Option<String>,
    pub listen: Vec<String>,
    pub data_dir: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (space_id, bootnode) = parse_bootstrap(&args.bootstrap)?;

    // Validate the bootnode multiaddr early so we don't write an
    // index entry the user can't actually use.
    let _ = bootnode
        .parse::<libp2p::Multiaddr>()
        .map_err(|e| anyhow::anyhow!("bad bootnode multiaddr '{bootnode}': {e}"))?;

    // Resolve the registry blob — explicit --registry, else
    // bundled. The bytes are cached under `registry_hash` so
    // `space up` finds them by hash.
    let (registry_hash, _bytes, registry_label) =
        resolve_registry_source(args.registry.as_deref())?;

    // Generate a per-space libp2p keypair (unique to this node
    // for this space — same per-space-identity story as
    // `space new`).
    let keypair = libp2p::identity::Keypair::generate_ed25519();

    let default_name = paths::space_id_hex(&space_id)
        .chars()
        .take(8)
        .collect::<String>();
    let name = args.name.unwrap_or(default_name);

    // Lay out the per-space data dir.
    let space_dir = args
        .data_dir
        .unwrap_or_else(|| paths::space_dir(&space_id));
    if space_dir.exists() {
        anyhow::bail!(
            "space data dir already exists: {} \
             (use `vosx space up <id>` to start an already-joined space)",
            space_dir.display(),
        );
    }
    std::fs::create_dir_all(&space_dir)?;
    std::fs::create_dir_all(space_dir.join("agents"))?;

    let key_bytes = keypair.to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("encode keypair: {e}"))?;
    std::fs::write(space_dir.join("node.key"), key_bytes)?;

    // Index entry.
    let mut index = spaces_index::load().unwrap_or_else(|_| SpacesIndex::default());
    let mut entry = spaces_index::entry_for(&space_id, &name, args.listen.clone());
    entry.data_dir = space_dir.to_string_lossy().to_string();
    entry.registry_hash = registry_hash.to_hex();
    entry.bootnodes = vec![bootnode.clone()];
    spaces_index::upsert(&mut index, entry);
    spaces_index::save(&index)?;

    let space_id_hex = paths::space_id_hex(&space_id);
    println!("joined space '{name}'");
    println!("  space_id  = {space_id_hex}");
    println!("  data_dir  = {}", space_dir.display());
    println!("  bootnode  = {bootnode}");
    println!("  registry  = {registry_label} ({registry_hash})");
    println!();
    println!("note: space_id is taken on trust from the bootstrap address. ");
    println!("      verification against genesis DAG root lands when the");
    println!("      placeholder space_id derivation is replaced.");
    println!();
    println!("run `vosx space up {name}` to dial the bootnode and start syncing.");

    Ok(())
}

/// Parse `<space-id>@<bootnode-multiaddr>`. The space_id half is
/// 64 hex chars; the bootnode half is whatever follows the `@`.
/// Whitespace around the separator is tolerated since users
/// often paste from logs.
fn parse_bootstrap(s: &str) -> anyhow::Result<([u8; 32], String)> {
    let trimmed = s.trim();
    let Some((id_str, addr_str)) = trimmed.split_once('@') else {
        anyhow::bail!(
            "bootstrap address must be '<space-id>@<bootnode-multiaddr>', got '{s}'"
        );
    };
    let id_str = id_str.trim();
    let addr_str = addr_str.trim();
    if id_str.len() != 64 {
        anyhow::bail!("space-id must be 64 hex chars, got {}", id_str.len());
    }
    let v = hex::decode(id_str).map_err(|_| anyhow::anyhow!("space-id is not hex"))?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&v);
    Ok((id, addr_str.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_bootstrap() {
        let id_hex = "a".repeat(64);
        let s = format!("{id_hex}@/ip4/127.0.0.1/tcp/4811");
        let (id, addr) = parse_bootstrap(&s).unwrap();
        assert_eq!(hex::encode(id), id_hex);
        assert_eq!(addr, "/ip4/127.0.0.1/tcp/4811");
    }

    #[test]
    fn parses_with_whitespace() {
        let id_hex = "b".repeat(64);
        let s = format!("  {id_hex} @ /ip4/127.0.0.1/tcp/4811  ");
        let (id, addr) = parse_bootstrap(&s).unwrap();
        assert_eq!(hex::encode(id), id_hex);
        assert_eq!(addr, "/ip4/127.0.0.1/tcp/4811");
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(parse_bootstrap("not-an-id-no-separator").is_err());
    }

    #[test]
    fn rejects_short_id() {
        assert!(parse_bootstrap("abc@/ip4/127.0.0.1/tcp/1").is_err());
    }
}
