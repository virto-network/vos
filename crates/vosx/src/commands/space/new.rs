//! `space new` — scaffold a fresh space.
//!
//! Phase 1a: derives a placeholder `space_id` from the
//! creator's keypair + a random nonce. Phase 1b will replace
//! this with the genesis-DAG-rooted derivation by booting the
//! registry actor and reading its first commit hash.

use std::path::PathBuf;

use crate::blob_store::{self, BlobSource};
use crate::paths;
use crate::spaces_index::{self, SpacesIndex};

pub struct Args {
    pub name: String,
    pub registry: String,
    pub listen: Vec<String>,
    pub data_dir: Option<PathBuf>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    if args.name.is_empty() {
        anyhow::bail!("--name is required and must be non-empty");
    }

    // 1. Resolve and cache the registry blob. Errors loud if the
    //    source is unreachable so we don't leave half-state.
    let source = BlobSource::parse(&args.registry);
    let (registry_hash, _registry_bytes) = blob_store::resolve(&source)
        .map_err(|e| anyhow::anyhow!("registry blob: {e}"))?;

    // 2. Generate a per-space libp2p keypair.
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let pubkey = keypair.public().encode_protobuf();

    // 3. PHASE 1a: placeholder space_id. Mixes creator pubkey
    //    with a random nonce so two `space new` invocations
    //    by the same creator produce distinct ids. Phase 1b
    //    replaces this with `derive_space_id(genesis_dag_root)`
    //    once the registry is actually booted.
    let space_id = placeholder_space_id(&args.name, &pubkey);

    // 4. Lay out the per-space data directory.
    let space_dir = args
        .data_dir
        .unwrap_or_else(|| paths::space_dir(&space_id));
    if space_dir.exists() {
        anyhow::bail!(
            "space data dir already exists: {}",
            space_dir.display()
        );
    }
    std::fs::create_dir_all(&space_dir)?;
    std::fs::create_dir_all(space_dir.join("agents"))?;

    // 5. Persist the keypair as protobuf bytes (matches the
    //    format `identity::load_or_generate_identity` reads).
    let key_path = space_dir.join("node.key");
    let key_bytes = keypair.to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("encode keypair: {e}"))?;
    std::fs::write(&key_path, key_bytes)?;

    // 6. Append to the spaces index.
    let mut index = spaces_index::load().unwrap_or_else(|_| SpacesIndex::default());
    let mut entry = spaces_index::entry_for(&space_id, &args.name, args.listen.clone());
    entry.data_dir = space_dir.to_string_lossy().to_string();
    spaces_index::upsert(&mut index, entry);
    spaces_index::save(&index)?;

    // 7. Print the result so the user can copy the bootnode line.
    let space_id_hex = paths::space_id_hex(&space_id);
    println!("created space '{}'", args.name);
    println!("  space_id   = {space_id_hex}");
    println!("  data_dir   = {}", space_dir.display());
    println!("  node.key   = {}", key_path.display());
    println!("  registry   = {} ({})", args.registry, registry_hash);
    if !args.listen.is_empty() {
        println!("  listen     =");
        for addr in &args.listen {
            println!("    {addr}");
        }
        let peer_id = libp2p::PeerId::from(keypair.public());
        println!("  bootnode hint:");
        println!(
            "    {space_id_hex}@{}/p2p/{peer_id}",
            args.listen[0],
        );
    }
    println!();
    println!("note: phase-1a space_id is a placeholder; Phase 1b will");
    println!("replace it with a genesis-DAG-rooted hash.");

    Ok(())
}

/// Placeholder space_id: blake2b("vos-space-id-placeholder/v0a"
/// || name || 0 || pubkey || 0 || nonce). The nonce defends
/// against two creators with the same name colliding.
fn placeholder_space_id(name: &str, pubkey: &[u8]) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-space-id-placeholder/v0a");
    h.update(&[0u8]);
    h.update(name.as_bytes());
    h.update(&[0u8]);
    h.update(pubkey);
    h.update(&[0u8]);
    let nonce_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(&nonce_ns.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}
