//! `space members` — Node + Identity membership management.
//!
//! CRUD over the registry's members table. The registry
//! stores Identity proofs verbatim; consumer-side verification
//! (an agent checking that an identity-authored message has a
//! valid proof against the registry's merkle root before
//! accepting it) is a separate consumer concern.

use clap::Subcommand;

use vos::registry::{MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, NODE_ROLE_OBSERVER, NODE_ROLE_VOTER, PROOF_KIND_MERKLE_INCLUSION, PROOF_KIND_ZK, Status};

use serde::Serialize;

use crate::commands::space::client::DaemonClient;
use crate::output;

// Hex-string fields drop the `_hex` suffix to match the
// convention used by ProgramView / AgentView / InfoView (where
// every byte field is just a bare hex string). `prefix` stays a
// numeric u16 — JSON consumers can format it however they want
// without paying a parse step.

#[derive(Serialize)]
struct NodeView {
    prefix: u16,
    peer_id: String,
    role: &'static str,
}

#[derive(Serialize)]
struct IdentityView {
    public_key: String,
    proof_kind: &'static str,
}

#[derive(Serialize)]
struct MembersView {
    nodes: Vec<NodeView>,
    identities: Vec<IdentityView>,
}

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
        /// Hex-encoded proof bytes. The registry stores
        /// these verbatim; verification is a consumer-side
        /// concern (an agent that wants to authenticate an
        /// identity-authored message looks the proof up in
        /// the members table and checks it against the
        /// registry's merkle root).
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
        MembersCommand::AddNode {
            peer_id,
            prefix,
            role,
        } => add_node(&args.space, &peer_id, prefix, &role),
        MembersCommand::RemoveNode { prefix } => remove_node(&args.space, prefix),
        MembersCommand::AddIdentity {
            public_key,
            proof_kind,
            proof_data,
        } => add_identity(&args.space, &public_key, &proof_kind, proof_data.as_deref()),
        MembersCommand::RemoveIdentity { public_key } => remove_identity(&args.space, &public_key),
    }
}

fn list(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let members = client.members()?;
        let nodes: Vec<_> = members
            .iter()
            .filter(|m| m.kind == MEMBER_KIND_NODE)
            .collect();
        let identities: Vec<_> = members
            .iter()
            .filter(|m| m.kind == MEMBER_KIND_IDENTITY)
            .collect();

        if output::is_json() {
            let view = MembersView {
                nodes: nodes
                    .iter()
                    .map(|n| NodeView {
                        prefix: n.prefix,
                        peer_id: hex::encode(&n.key),
                        role: role_name(n.role),
                    })
                    .collect(),
                identities: identities
                    .iter()
                    .map(|i| IdentityView {
                        public_key: hex::encode(&i.key),
                        proof_kind: proof_kind_name(i.proof_kind),
                    })
                    .collect(),
            };
            output::print_json(&view);
            return Ok(());
        }

        if !nodes.is_empty() {
            println!("# nodes");
            println!("{:<8}  {:<10}  PEER_ID", "PREFIX", "ROLE");
            for n in &nodes {
                let short_pid: String = hex::encode(&n.key).chars().take(20).collect();
                println!("{:<8}  {:<10}  {short_pid}…", n.prefix, role_name(n.role));
            }
        }
        if !identities.is_empty() {
            if !nodes.is_empty() {
                println!();
            }
            println!("# identities");
            println!("{:<10}  PUBLIC_KEY", "PROOF");
            for i in &identities {
                let short_pk: String = hex::encode(&i.key).chars().take(20).collect();
                println!("{:<10}  {short_pk}…", proof_kind_name(i.proof_kind));
            }
        }
        if nodes.is_empty() && identities.is_empty() {
            println!(
                "no members. add one with `vosx space members add-node …` or `add-identity …`."
            );
        }
        Ok(())
    })
}

fn role_name(r: u8) -> &'static str {
    match r {
        NODE_ROLE_VOTER => "voter",
        NODE_ROLE_OBSERVER => "observer",
        _ => "?",
    }
}

fn proof_kind_name(k: u8) -> &'static str {
    match k {
        PROOF_KIND_MERKLE_INCLUSION => "merkle",
        PROOF_KIND_ZK => "zk",
        _ => "?",
    }
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
    let prefix =
        prefix_override.unwrap_or_else(|| vos::network::derive_node_prefix(&peer_id) as u32);
    let role = match role_str {
        "voter" => NODE_ROLE_VOTER,
        "observer" => NODE_ROLE_OBSERVER,
        other => anyhow::bail!("unknown role '{other}', expected voter|observer"),
    };

    DaemonClient::with_connect(space, |client| {
        let status = client.add_node(prefix, peer_id.to_bytes(), role)?;
        if status != Status::Ok {
            anyhow::bail!("add_node returned status {status}");
        }
        if output::is_json() {
            #[derive(Serialize)]
            struct V<'a> {
                prefix: u16,
                role: &'a str,
            }
            output::print_json(&V {
                prefix: prefix as u16,
                role: role_str,
            });
        } else {
            println!("added node prefix=0x{:04x} role={role_str}", prefix as u16);
        }
        Ok(())
    })
}

fn remove_node(space: &str, prefix: u32) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| match client.remove_node(prefix)? {
        Status::Ok => {
            if output::is_json() {
                #[derive(Serialize)]
                struct V {
                    prefix: u16,
                }
                output::print_json(&V {
                    prefix: prefix as u16,
                });
            } else {
                println!("removed node prefix=0x{:04x}", prefix as u16);
            }
            Ok(())
        }
        Status::NotFound => anyhow::bail!("no node with prefix 0x{:04x}", prefix as u16),
        other => anyhow::bail!("remove_node returned status {other}"),
    })
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

    DaemonClient::with_connect(space, |client| {
        let status = client.add_identity(pubkey.clone(), proof_kind, proof_data)?;
        if status != Status::Ok {
            anyhow::bail!("add_identity returned status {status}");
        }
        if output::is_json() {
            #[derive(Serialize)]
            struct V<'a> {
                public_key: String,
                proof_kind: &'a str,
            }
            output::print_json(&V {
                public_key: hex::encode(&pubkey),
                proof_kind: proof_kind_str,
            });
        } else {
            println!(
                "added identity {} (proof={proof_kind_str})",
                &hex::encode(&pubkey)[..20.min(pubkey.len() * 2)],
            );
        }
        Ok(())
    })
}

fn remove_identity(space: &str, pubkey_hex: &str) -> anyhow::Result<()> {
    let pubkey = hex::decode(pubkey_hex.trim_start_matches("0x"))
        .map_err(|_| anyhow::anyhow!("public_key must be hex"))?;
    DaemonClient::with_connect(space, |client| {
        match client.remove_identity(pubkey.clone())? {
            Status::Ok => {
                if output::is_json() {
                    #[derive(Serialize)]
                    struct V {
                        public_key: String,
                    }
                    output::print_json(&V {
                        public_key: hex::encode(&pubkey),
                    });
                } else {
                    println!("removed identity");
                }
                Ok(())
            }
            Status::NotFound => anyhow::bail!("no identity with that public key"),
            other => anyhow::bail!("remove_identity returned status {other}"),
        }
    })
}
