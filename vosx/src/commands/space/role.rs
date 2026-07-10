//! `vosx space role` — list, grant, revoke auth role grants.
//!
//! Two grant scopes:
//!
//! - **Space-level**: `<peer> -> <SpaceRole>`. Applied as a
//!   fallback by every actor via its [`SPACE_ROLE_MAP`]. The
//!   common case.
//! - **Actor-local** (M8, `--in <actor>`): `<peer, agent_name>
//!   -> <actor's Role byte>`. Overrides the space-level mapping
//!   for that specific actor. Useful for "Bob is a regular
//!   Member but I need him to maintain dev-project".
//!
//! Layout:
//!
//! ```text
//! vosx space role <space> list                                 # default
//! vosx space role <space> grant <peer> <role>                  # space-level
//! vosx space role <space> grant <peer> <role> --in <actor>     # actor-local
//! vosx space role <space> revoke <peer>                        # space-level
//! vosx space role <space> revoke <peer> --in <actor>           # actor-local
//! ```
//!
//! The `<peer>` argument accepts:
//! - `me` — shortcut for the operator's persistent identity
//!   (`vosx whoami` PeerId). Convenient for self-enrollment via
//!   another admin's CLI.
//! - A multibase-encoded libp2p PeerId (`12D3KooW…`).
//!
//! For actor-local grants, `<role>` is the *target actor's*
//! role byte (parsed as a decimal `0..255`); the registry stores
//! it opaquely. v1 doesn't query the actor's role-name table —
//! operators reference the discriminant directly.

use clap::Subcommand;
use serde::Serialize;
use vos::registry::{AUTH_ROLE_ADMIN, AUTH_ROLE_DEVELOPER, AUTH_ROLE_NONE, AUTH_ROLE_READONLY, Status};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Subcommand, Debug)]
pub enum RoleCommand {
    /// List auth grants. With `--in <actor>`, lists actor-local
    /// grants; without, lists space-level grants.
    List {
        /// Show actor-local grants for this agent instead of
        /// space-level grants.
        #[arg(long = "in", value_name = "ACTOR")]
        agent: Option<String>,
    },
    /// Grant a role to a peer. Overwrites any existing grant.
    Grant {
        /// Multibase-encoded libp2p PeerId (`12D3KooW…`) or
        /// the literal `me` for the operator's
        /// `$XDG_CONFIG_HOME/vosx/identity.key`.
        peer: String,
        /// Space-level: `admin`, `developer`, `read`, `none`.
        /// Actor-local (with `--in`): a numeric role byte
        /// interpreted in the target actor's `Role` enum.
        role: String,
        /// Scope the grant to a specific actor instance,
        /// overriding the space-level mapping for that actor.
        #[arg(long = "in", value_name = "ACTOR")]
        agent: Option<String>,
    },
    /// Remove a peer's grant. Equivalent to `grant <peer> none`
    /// but also removes the table row so listings stay tidy.
    Revoke {
        /// Same accepted forms as `grant`.
        peer: String,
        /// Scope the revocation to a specific actor instance.
        /// Space-level grant is unaffected.
        #[arg(long = "in", value_name = "ACTOR")]
        agent: Option<String>,
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
    match args.command.unwrap_or(RoleCommand::List { agent: None }) {
        RoleCommand::List { agent } => list(&args.space, agent.as_deref()),
        RoleCommand::Grant { peer, role, agent } => {
            grant(&args.space, &peer, &role, agent.as_deref())
        }
        RoleCommand::Revoke { peer, agent } => revoke(&args.space, &peer, agent.as_deref()),
    }
}

fn list(space: &str, agent: Option<&str>) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| match agent {
        // Actor-local listing — rows are (peer, agent, role byte)
        // tuples; role is opaque to the CLI in v1.
        Some(name) => {
            let grants = client.actor_acls()?;
            let filtered: Vec<_> = grants.iter().filter(|g| g.agent_name == name).collect();
            if output::is_json() {
                #[derive(Serialize)]
                struct ActorGrantView {
                    peer_id: String,
                    agent: String,
                    role: u8,
                }
                let view: Vec<ActorGrantView> = filtered
                    .iter()
                    .map(|g| ActorGrantView {
                        peer_id: peer_id_label(&g.peer_id),
                        agent: g.agent_name.clone(),
                        role: g.role,
                    })
                    .collect();
                output::print_json(&view);
                return Ok(());
            }
            if filtered.is_empty() {
                println!(
                    "no actor-local grants for '{name}'. add one with \
                     `vosx space role grant <peer> <role-byte> --in {name}`."
                );
                return Ok(());
            }
            println!("{:<5}  PEER_ID", "ROLE");
            for g in &filtered {
                println!("{:<5}  {}", g.role, peer_id_label(&g.peer_id));
            }
            Ok(())
        }
        None => {
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
        }
    })
}

fn grant(space: &str, peer_arg: &str, role_str: &str, agent: Option<&str>) -> anyhow::Result<()> {
    let peer_id = resolve_peer(peer_arg)?;
    DaemonClient::with_connect(space, |client| match agent {
        Some(name) => {
            // Actor-local: parse role as a raw byte the registry
            // stores opaquely. Operator looks up the discriminant
            // in the actor's Role enum (v1 doesn't surface a
            // name table).
            let role: u8 = role_str
                .parse()
                .map_err(|_| anyhow::anyhow!("actor-local role must be a 0..255 byte"))?;
            let status = client.grant_actor_role(peer_id.to_bytes(), name.to_string(), role)?;
            if status != Status::Ok {
                anyhow::bail!("grant_actor_role returned status {status}");
            }
            if output::is_json() {
                #[derive(Serialize)]
                struct V {
                    peer_id: String,
                    agent: String,
                    role: u8,
                }
                output::print_json(&V {
                    peer_id: peer_id.to_string(),
                    agent: name.to_string(),
                    role,
                });
            } else {
                println!("granted role {role} to {peer_id} in {name}");
            }
            Ok(())
        }
        None => {
            let role = parse_role(role_str)?;
            let status = client.grant_role(peer_id.to_bytes(), role)?;
            if status != Status::Ok {
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
        }
    })
}

fn revoke(space: &str, peer_arg: &str, agent: Option<&str>) -> anyhow::Result<()> {
    let peer_id = resolve_peer(peer_arg)?;
    DaemonClient::with_connect(space, |client| {
        let status = match agent {
            Some(name) => client.revoke_actor_role(peer_id.to_bytes(), name.to_string())?,
            None => client.revoke_role(peer_id.to_bytes())?,
        };
        match status {
            Status::Ok => {
                if output::is_json() {
                    #[derive(Serialize)]
                    struct V {
                        peer_id: String,
                        agent: Option<String>,
                    }
                    output::print_json(&V {
                        peer_id: peer_id.to_string(),
                        agent: agent.map(String::from),
                    });
                } else if let Some(name) = agent {
                    println!("revoked actor-local grant for {peer_id} in {name}");
                } else {
                    println!("revoked grant for {peer_id}");
                }
                Ok(())
            }
            Status::NotFound => match agent {
                Some(name) => anyhow::bail!("no actor-local grant for {peer_id} in {name}"),
                None => anyhow::bail!("no grant for {peer_id}"),
            },
            other => anyhow::bail!("revoke returned status {other}"),
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
