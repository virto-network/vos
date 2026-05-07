//! `space members` — Node + Identity membership management.
//!
//! Phase 3 covers the CRUD surface; the consumer-side
//! verification (an agent checking that an identity-authored
//! message has a valid proof against the registry's merkle
//! root) lands later. For now the registry stores proofs
//! verbatim and the display commands surface them.

use clap::Subcommand;

use vos::abi::service::ServiceId;
use space_registry::{
    SpaceRegistryRef, MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, NODE_ROLE_OBSERVER,
    NODE_ROLE_VOTER, PROOF_KIND_MERKLE_INCLUSION, PROOF_KIND_ZK, STATUS_NOT_FOUND,
    STATUS_OK,
};

use crate::commands::space::transient::TransientRegistry;

#[derive(Subcommand, Debug)]
pub enum MembersCommand {
    /// List members (default if no subcommand given).
    List,
    /// Add a Node member (libp2p peer that may participate in
    /// consensus).
    AddNode {
        /// Multibase-encoded libp2p PeerId (e.g. `12D3KooW…`).
        peer_id: String,
        /// 16-bit node prefix. Defaults to deriving from the
        /// peer_id (the same scheme `vos::network::derive_node_prefix`
        /// uses).
        #[arg(long)]
        prefix: Option<u32>,
        /// `voter` (default) or `observer`.
        #[arg(long, default_value = "voter")]
        role: String,
    },
    /// Remove a Node member by prefix.
    RemoveNode {
        /// 16-bit prefix.
        prefix: u32,
    },
    /// Add an Identity member (a key that authors signed
    /// messages, gated by a Merkle/ZK inclusion proof).
    AddIdentity {
        /// Hex-encoded public key (typically 32 bytes for
        /// ed25519).
        public_key: String,
        /// `merkle` (default) or `zk`.
        #[arg(long, default_value = "merkle")]
        proof_kind: String,
        /// Hex-encoded proof bytes. Optional — Phase 3 stores
        /// the proof verbatim; verification happens later.
        #[arg(long, value_name = "HEX")]
        proof_data: Option<String>,
    },
    /// Remove an Identity member by public key.
    RemoveIdentity { public_key: String },
}

pub struct Args {
    pub space: String,
    pub command: Option<MembersCommand>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command.unwrap_or(MembersCommand::List) {
        MembersCommand::List => list(&args.space),
        MembersCommand::AddNode { peer_id, prefix, role } => {
            add_node(&args.space, &peer_id, prefix, &role)
        }
        MembersCommand::RemoveNode { prefix } => remove_node(&args.space, prefix),
        MembersCommand::AddIdentity {
            public_key,
            proof_kind,
            proof_data,
        } => add_identity(&args.space, &public_key, &proof_kind, proof_data.as_deref()),
        MembersCommand::RemoveIdentity { public_key } => {
            remove_identity(&args.space, &public_key)
        }
    }
}

fn list(space: &str) -> anyhow::Result<()> {
    let h = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let members = vos::block_on(reg.members(&mut &*h.node()))
        .map_err(|e| anyhow::anyhow!("members() failed: {e}"))?;

    let nodes: Vec<_> = members.iter().filter(|m| m.kind == MEMBER_KIND_NODE).collect();
    let identities: Vec<_> = members
        .iter()
        .filter(|m| m.kind == MEMBER_KIND_IDENTITY)
        .collect();

    if !nodes.is_empty() {
        println!("# nodes");
        println!("{:<8}  {:<10}  PEER_ID", "PREFIX", "ROLE");
        for n in &nodes {
            let role = match n.role {
                NODE_ROLE_VOTER => "voter",
                NODE_ROLE_OBSERVER => "observer",
                _ => "?",
            };
            let short_pid: String = hex::encode(&n.key).chars().take(20).collect();
            println!("{:<8}  {:<10}  {short_pid}…", n.prefix, role);
        }
    }
    if !identities.is_empty() {
        if !nodes.is_empty() {
            println!();
        }
        println!("# identities");
        println!("{:<10}  PUBLIC_KEY", "PROOF");
        for i in &identities {
            let proof = match i.proof_kind {
                PROOF_KIND_MERKLE_INCLUSION => "merkle",
                PROOF_KIND_ZK => "zk",
                _ => "?",
            };
            let short_pk: String = hex::encode(&i.key).chars().take(20).collect();
            println!("{:<10}  {short_pk}…", proof);
        }
    }
    if nodes.is_empty() && identities.is_empty() {
        println!("no members. add one with `vosx space members add-node …` or `add-identity …`.");
    }
    h.shutdown()
}

fn add_node(
    space: &str,
    peer_id_str: &str,
    prefix_override: Option<u32>,
    role_str: &str,
) -> anyhow::Result<()> {
    let peer_id = peer_id_str
        .parse::<libp2p::PeerId>()
        .map_err(|e| anyhow::anyhow!("parse peer_id: {e}"))?;
    let prefix = prefix_override
        .unwrap_or_else(|| vos::network::derive_node_prefix(&peer_id) as u32);
    let role = match role_str {
        "voter" => NODE_ROLE_VOTER,
        "observer" => NODE_ROLE_OBSERVER,
        other => anyhow::bail!("unknown role '{other}', expected voter|observer"),
    };

    let h = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let status = vos::block_on(reg.add_node(
        &mut &*h.node(),
        prefix,
        peer_id.to_bytes(),
        role,
    ))
    .map_err(|e| anyhow::anyhow!("add_node() failed: {e}"))?;

    if status != STATUS_OK {
        anyhow::bail!("add_node returned status {status}");
    }
    println!("added node prefix=0x{:04x} role={role_str}", prefix as u16);
    h.shutdown()
}

fn remove_node(space: &str, prefix: u32) -> anyhow::Result<()> {
    let h = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let status = vos::block_on(reg.remove_node(&mut &*h.node(), prefix))
        .map_err(|e| anyhow::anyhow!("remove_node() failed: {e}"))?;
    match status {
        STATUS_OK => println!("removed node prefix=0x{:04x}", prefix as u16),
        STATUS_NOT_FOUND => anyhow::bail!("no node with prefix 0x{:04x}", prefix as u16),
        other => anyhow::bail!("remove_node returned status {other}"),
    }
    h.shutdown()
}

fn add_identity(
    space: &str,
    pubkey_hex: &str,
    proof_kind_str: &str,
    proof_data_hex: Option<&str>,
) -> anyhow::Result<()> {
    let pubkey = hex::decode(pubkey_hex.trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("public_key must be hex"))?;
    let proof_kind = match proof_kind_str {
        "merkle" => PROOF_KIND_MERKLE_INCLUSION,
        "zk" => PROOF_KIND_ZK,
        other => anyhow::bail!("unknown proof kind '{other}', expected merkle|zk"),
    };
    let proof_data = match proof_data_hex {
        Some(h) => hex::decode(h.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("proof_data must be hex"))?,
        None => Vec::new(),
    };

    let h = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let status = vos::block_on(reg.add_identity(
        &mut &*h.node(),
        pubkey.clone(),
        proof_kind,
        proof_data,
    ))
    .map_err(|e| anyhow::anyhow!("add_identity() failed: {e}"))?;
    if status != STATUS_OK {
        anyhow::bail!("add_identity returned status {status}");
    }
    println!(
        "added identity {} (proof={proof_kind_str})",
        &hex::encode(&pubkey)[..20.min(pubkey.len() * 2)],
    );
    h.shutdown()
}

fn remove_identity(space: &str, pubkey_hex: &str) -> anyhow::Result<()> {
    let pubkey = hex::decode(pubkey_hex.trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("public_key must be hex"))?;
    let h = TransientRegistry::boot(space)?;
    let reg = SpaceRegistryRef::at(ServiceId::REGISTRY);
    let status = vos::block_on(reg.remove_identity(&mut &*h.node(), pubkey))
        .map_err(|e| anyhow::anyhow!("remove_identity() failed: {e}"))?;
    match status {
        STATUS_OK => println!("removed identity"),
        STATUS_NOT_FOUND => anyhow::bail!("no identity with that public key"),
        other => anyhow::bail!("remove_identity returned status {other}"),
    }
    h.shutdown()
}
