//! `space invite` — mint a `vos1…` invite token.
//!
//! An invite is a pointer + credential, never policy (decision 3): it
//! carries the space id, name, bootnodes, a role, an expiry, and an
//! admin-signed delegated-grant chain. A joiner runs `space up <token>`
//! and the daemon redeems it against a bootnode, which grants the
//! joiner's node key the role — what that role may sync/spawn lives in
//! the registry and can evolve after the token is minted.
//!
//! Minting requires the operator to hold ADMIN in the target space
//! (the delegated-grant chain is admin → token → node). Offline-
//! redeemable tiers are `member` and `developer`; `admin` needs online
//! admission (decision 5) and prints a caveat.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use vos::registry::{AUTH_ROLE_ADMIN, AUTH_ROLE_DEVELOPER, AUTH_ROLE_READONLY};

use crate::commands::space::client::DaemonClient;
use crate::output;
use crate::token;

pub struct Args {
    pub space: String,
    /// `member` | `developer` | `admin`.
    pub role: String,
    /// Expiry window: `7d` / `24h` / `30m` / `90s` / bare seconds.
    pub expires: String,
    /// Bootnode multiaddr(s) to embed. Defaults to the running daemon's
    /// published listen addrs.
    pub bootnode: Vec<String>,
}

#[derive(Serialize)]
struct InviteView<'a> {
    token: &'a str,
    space: &'a str,
    role: &'a str,
    expires_at: u64,
    bootnodes: &'a [String],
}

/// Map a user-facing role name to its `AUTH_ROLE_*` code (decision 12 —
/// CLI names, not numbers, mapped in one place). Returns the code plus
/// the canonical spelling to echo back.
fn role_from_name(s: &str) -> anyhow::Result<(u8, &'static str)> {
    match s.to_ascii_lowercase().as_str() {
        "member" | "read" | "readonly" | "read-only" => Ok((AUTH_ROLE_READONLY, "member")),
        "developer" | "dev" => Ok((AUTH_ROLE_DEVELOPER, "developer")),
        "admin" => Ok((AUTH_ROLE_ADMIN, "admin")),
        other => anyhow::bail!("unknown role '{other}', expected member|developer|admin"),
    }
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (role, role_name) = role_from_name(&args.role)?;
    let ttl = token::parse_duration(&args.expires)?;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + ttl;

    // Validate any explicit bootnodes early so we don't mint a token
    // that embeds an unusable address.
    for b in &args.bootnode {
        b.parse::<libp2p::Multiaddr>()
            .map_err(|e| anyhow::anyhow!("bad --bootnode multiaddr '{b}': {e}"))?;
    }

    // Load the operator key that signs the invite (the delegated-grant
    // chain's root). Same identity the daemon sees as `Caller::Peer`.
    let operator = crate::identity::load_or_create()?;
    let operator_peer = libp2p::PeerId::from(operator.public()).to_bytes();

    DaemonClient::with_connect(&args.space, |client| {
        // Refuse unless the operator holds ADMIN — a non-admin's invite
        // would fail `redeem_invite`'s `is_effective_admin` check anyway,
        // so fail here with a clear message instead of minting a dud.
        let op_role = client.peer_role(operator_peer.clone())?;
        if op_role < AUTH_ROLE_ADMIN {
            anyhow::bail!(
                "minting an invite requires ADMIN in space '{}'; this operator holds {}. \
                 Ask an admin to `space role {} grant <your-peer-id> admin`, or mint from the \
                 admin node.",
                client.entry.name,
                role_label(op_role),
                client.entry.name,
            );
        }

        let space_id = client
            .entry
            .id_bytes()
            .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;

        // Default bootnodes: the running daemon's published multiaddrs.
        let bootnodes = if args.bootnode.is_empty() {
            client.endpoint.multiaddrs.clone()
        } else {
            args.bootnode.clone()
        };
        if bootnodes.is_empty() {
            anyhow::bail!(
                "the daemon published no listen multiaddrs to embed as bootnodes — pass \
                 `--bootnode <multiaddr>` (a reachable address of this node)",
            );
        }

        let tok = token::mint(
            &operator,
            space_id,
            client.entry.name.clone(),
            bootnodes.clone(),
            role,
            expires_at,
        )?;

        if output::is_json() {
            output::print_json(&InviteView {
                token: &tok,
                space: &client.entry.name,
                role: role_name,
                expires_at,
                bootnodes: &bootnodes,
            });
        } else {
            println!("{tok}");
            println!();
            println!("invite for space '{}'", client.entry.name);
            println!("  role      = {role_name}");
            println!("  expires   = {} (in {})", expires_at, args.expires);
            println!("  bootnodes = {}", bootnodes.join(", "));
            println!();
            if role == AUTH_ROLE_ADMIN {
                println!(
                    "note: `admin` is online-admission only — an offline `space up <token>` \
                     redeem is refused by the registry. The serving admin must countersign the \
                     grant. Prefer `--role developer` for delegated authoring.",
                );
            } else {
                println!("redeem with: `vosx space up <token>` (or `vosx space up -` to pipe it in).");
            }
        }
        Ok(())
    })
}

fn role_label(role: u8) -> &'static str {
    match role {
        AUTH_ROLE_ADMIN => "admin",
        AUTH_ROLE_DEVELOPER => "developer",
        AUTH_ROLE_READONLY => "member",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_map_to_auth_codes() {
        assert_eq!(role_from_name("member").unwrap(), (AUTH_ROLE_READONLY, "member"));
        assert_eq!(role_from_name("Developer").unwrap().0, AUTH_ROLE_DEVELOPER);
        assert_eq!(role_from_name("admin").unwrap().0, AUTH_ROLE_ADMIN);
        assert!(role_from_name("wizard").is_err());
    }
}
