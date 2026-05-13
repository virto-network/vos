//! `vosx space role` — list, grant, revoke auth role grants.
//!
//! Sprint 2: the dispatch-layer auth gate in `vos::node` consults
//! the registry's `auth_grants` table for every libp2p-originated
//! call to a privileged registry handler (publish, install, …).
//! This subcommand is the operator-facing surface for managing
//! the table.
//!
//! Layout:
//!
//! ```text
//! vosx space role <space> list                       # default
//! vosx space role <space> grant <peer> <role>        # admin|developer|read|none
//! vosx space role <space> revoke <peer>
//! ```
//!
//! The `<peer>` argument accepts:
//! - `me` — shortcut for the operator's persistent identity
//!   (`vosx whoami` PeerId). Convenient for self-enrollment via
//!   another admin's CLI.
//! - A multibase-encoded libp2p PeerId (`12D3KooW…`).

use clap::Subcommand;
use serde::Serialize;
use space_registry::{
    AUTH_ROLE_ADMIN, AUTH_ROLE_DEVELOPER, AUTH_ROLE_NONE, AUTH_ROLE_READONLY, STATUS_NOT_FOUND,
    STATUS_OK,
};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Subcommand, Debug)]
pub enum RoleCommand {
    /// List auth grants. Default if no subcommand given.
    List,
    /// Grant a role to a peer. Overwrites any existing grant.
    Grant {
        /// Multibase-encoded libp2p PeerId (`12D3KooW…`) or
        /// the literal `me` for the operator's
        /// `$XDG_CONFIG_HOME/vosx/identity.key`.
        peer: String,
        /// One of: `admin`, `developer`, `read`, `none`.
        role: String,
    },
    /// Remove a peer's grant. Equivalent to `grant <peer> none`
    /// but also removes the table row so listings stay tidy.
    Revoke {
        /// Same accepted forms as `grant`.
        peer: String,
    },
}

pub struct Args {
    pub space: String,
    pub command: Option<RoleCommand>,
}

#[derive(Serialize)]
struct GrantView {
    peer_id: String,
    role: &'static str,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command.unwrap_or(RoleCommand::List) {
        RoleCommand::List => list(&args.space),
        RoleCommand::Grant { peer, role } => grant(&args.space, &peer, &role),
        RoleCommand::Revoke { peer } => revoke(&args.space, &peer),
    }
}

fn list(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let grants = client.auth_grants()?;
        if output::is_json() {
            let view: Vec<GrantView> = grants
                .iter()
                .map(|g| GrantView {
                    peer_id: peer_id_label(&g.peer_id),
                    role: role_name(g.role),
                })
                .collect();
            output::print_json(&view);
            return Ok(());
        }
        if grants.is_empty() {
            println!("no auth grants. add one with `vosx space role grant <peer> <role>`.");
            return Ok(());
        }
        println!("{:<10}  PEER_ID", "ROLE");
        for g in &grants {
            println!("{:<10}  {}", role_name(g.role), peer_id_label(&g.peer_id));
        }
        Ok(())
    })
}

fn grant(space: &str, peer_arg: &str, role_str: &str) -> anyhow::Result<()> {
    let peer_id = resolve_peer(peer_arg)?;
    let role = parse_role(role_str)?;
    DaemonClient::with_connect(space, |client| {
        let status = client.grant_role(peer_id.to_bytes(), role)?;
        if status != STATUS_OK {
            anyhow::bail!("grant_role returned status {status}");
        }
        if output::is_json() {
            output::print_json(&GrantView {
                peer_id: peer_id.to_string(),
                role: role_name(role),
            });
        } else {
            println!("granted {} to {peer_id}", role_name(role));
        }
        Ok(())
    })
}

fn revoke(space: &str, peer_arg: &str) -> anyhow::Result<()> {
    let peer_id = resolve_peer(peer_arg)?;
    DaemonClient::with_connect(space, |client| {
        let status = client.revoke_role(peer_id.to_bytes())?;
        match status {
            STATUS_OK => {
                if output::is_json() {
                    #[derive(Serialize)]
                    struct V {
                        peer_id: String,
                    }
                    output::print_json(&V {
                        peer_id: peer_id.to_string(),
                    });
                } else {
                    println!("revoked grant for {peer_id}");
                }
                Ok(())
            }
            STATUS_NOT_FOUND => anyhow::bail!("no grant for {peer_id}"),
            other => anyhow::bail!("revoke_role returned status {other}"),
        }
    })
}

fn resolve_peer(arg: &str) -> anyhow::Result<libp2p::PeerId> {
    if arg == "me" {
        let kp = crate::identity::load_or_create()?;
        return Ok(libp2p::PeerId::from(kp.public()));
    }
    arg.parse::<libp2p::PeerId>()
        .map_err(|e| anyhow::anyhow!("parse peer '{arg}': {e}"))
}

fn parse_role(s: &str) -> anyhow::Result<u8> {
    match s {
        "admin" => Ok(AUTH_ROLE_ADMIN),
        "developer" | "dev" => Ok(AUTH_ROLE_DEVELOPER),
        "read" | "readonly" | "read-only" => Ok(AUTH_ROLE_READONLY),
        "none" => Ok(AUTH_ROLE_NONE),
        other => anyhow::bail!("unknown role '{other}'; expected: admin | developer | read | none"),
    }
}

fn role_name(r: u8) -> &'static str {
    match r {
        AUTH_ROLE_NONE => "none",
        AUTH_ROLE_READONLY => "read",
        AUTH_ROLE_DEVELOPER => "developer",
        AUTH_ROLE_ADMIN => "admin",
        _ => "?",
    }
}

/// Best-effort decode for display: libp2p PeerId if the bytes
/// parse, else hex. Operators paste PeerId strings, so the
/// happy path is the multibase form.
fn peer_id_label(bytes: &[u8]) -> String {
    match libp2p::PeerId::from_bytes(bytes) {
        Ok(p) => p.to_string(),
        Err(_) => hex::encode(bytes),
    }
}

#[cfg(test)]
#[allow(dead_code)] // touched in role::tests namespace; unused-import lint catches the placeholder.
fn _grant_view_used() -> &'static [GrantView] {
    &[]
}
