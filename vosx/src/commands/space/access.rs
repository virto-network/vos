//! Manage authority-owned access credentials for built-in ingress adapters.

use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use serde::Serialize;
use vos::{Decode, SpaceRole};

use super::client::DaemonClient;

#[derive(Subcommand, Debug)]
pub enum AccessCommand {
    /// Issue a bearer token. The secret is displayed once.
    Issue {
        /// `member`, `developer`, or `admin` (root operator only).
        #[arg(long, default_value = "member")]
        role: String,
        /// `24h`, `7d`, `30m`, `90s`, or bare seconds.
        #[arg(long, default_value = "24h")]
        expires: String,
    },
    /// List non-secret authority rows.
    List,
    /// Revoke an exact credential ID or an unambiguous hex prefix.
    Revoke { credential: String },
}

pub struct Args {
    pub space: String,
    pub command: AccessCommand,
}

#[derive(Serialize)]
struct IssuedAccess {
    token: String,
    credential_id: String,
    subject: String,
    role: &'static str,
    expires_at: u64,
}

#[derive(Serialize)]
struct AccessView {
    credential_id: String,
    subject: String,
    role: &'static str,
    expires_at: u64,
    revoked: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        AccessCommand::Issue { role, expires } => issue(&args.space, &role, &expires),
        AccessCommand::List => list(&args.space),
        AccessCommand::Revoke { credential } => revoke(&args.space, &credential),
    }
}

fn issue(space: &str, role: &str, expires: &str) -> anyhow::Result<()> {
    let role = parse_role(role)?;
    let ttl = crate::token::parse_duration(expires)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_at = now
        .checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("access expiry overflows Unix time"))?;
    let mut secret = [0_u8; 32];
    getrandom::getrandom(&mut secret)?;
    let credential_id = vos::ingress_credential_id(&secret);
    DaemonClient::with_connect(space, |client| {
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let message = vos::value::Msg::new("issue_access")
            .with("credential_id", credential_id.to_vec())
            .with("role", role.as_u8())
            .with("expires_at", expires_at);
        let value = client.invoke_dyn(target, &message)?;
        let bytes = value
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("authority returned an invalid access decision"))?;
        let status = vos::IngressAccessStatus::try_decode(bytes)
            .ok_or_else(|| anyhow::anyhow!("authority refused access issuance"))?;
        if status.credential_id != credential_id {
            anyhow::bail!("authority returned a mismatched credential");
        }
        let view = IssuedAccess {
            token: vos::ingress::encode_access_token(&secret),
            credential_id: hex::encode(credential_id),
            subject: hex::encode(status.subject),
            role: role_name(status.role),
            expires_at: status.expires_at,
        };
        if crate::output::is_json() {
            crate::output::print_json(&view);
        } else {
            println!("{}", view.token);
            eprintln!("credential  {}", view.credential_id);
            eprintln!("role        {}", view.role);
            eprintln!("expires_at  {}", view.expires_at);
        }
        Ok(())
    })
}

fn list(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let rows = access_rows(client)?;
        let views: Vec<_> = rows.iter().map(view).collect();
        if crate::output::is_json() {
            crate::output::print_json(&views);
        } else if views.is_empty() {
            println!("no ingress access credentials");
        } else {
            println!(
                "{:<14}  {:<10}  {:<10}  SUBJECT",
                "CREDENTIAL", "ROLE", "STATUS"
            );
            for row in views {
                println!(
                    "{:<14}  {:<10}  {:<10}  {}",
                    &row.credential_id[..12],
                    row.role,
                    if row.revoked { "revoked" } else { "active" },
                    &row.subject[..12],
                );
            }
        }
        Ok(())
    })
}

fn revoke(space: &str, selector: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let rows = access_rows(client)?;
        let matches: Vec<_> = rows
            .iter()
            .filter(|row| hex::encode(row.credential_id).starts_with(selector))
            .collect();
        let row = match matches.as_slice() {
            [row] => *row,
            [] => anyhow::bail!("no credential matches '{selector}'"),
            _ => anyhow::bail!("credential prefix '{selector}' is ambiguous"),
        };
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let message =
            vos::value::Msg::new("revoke_access").with("credential_id", row.credential_id.to_vec());
        if client.invoke_dyn(target, &message)?.as_bool() != Some(true) {
            anyhow::bail!("authority refused access revocation");
        }
        if crate::output::is_json() {
            crate::output::print_json(&serde_json::json!({
                "credential_id": hex::encode(row.credential_id),
                "revoked": true,
            }));
        } else {
            println!("revoked {}", hex::encode(row.credential_id));
        }
        Ok(())
    })
}

fn access_rows(client: &DaemonClient) -> anyhow::Result<Vec<vos::IngressAccessGrant>> {
    let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
    let mut rows = Vec::new();
    let mut after = Vec::new();
    loop {
        let message = vos::value::Msg::new("list_access")
            .with("after", after.clone())
            .with("budget", 128_u32);
        let value = client.invoke_dyn(target, &message)?;
        let bytes = value
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("authority returned an invalid access page"))?;
        let page = Vec::<vos::IngressAccessGrant>::try_decode(bytes)
            .ok_or_else(|| anyhow::anyhow!("decode authority access page"))?;
        let count = page.len();
        after = page
            .last()
            .map(|row| row.subject.to_vec())
            .unwrap_or_default();
        rows.extend(page);
        if count < 128 {
            break;
        }
    }
    Ok(rows)
}

fn parse_role(role: &str) -> anyhow::Result<SpaceRole> {
    match role.to_ascii_lowercase().as_str() {
        "member" | "read" => Ok(SpaceRole::Member),
        "developer" | "dev" => Ok(SpaceRole::Developer),
        "admin" => Ok(SpaceRole::Admin),
        _ => anyhow::bail!("unknown role '{role}', expected member|developer|admin"),
    }
}

fn role_name(role: SpaceRole) -> &'static str {
    match role {
        SpaceRole::Guest => "guest",
        SpaceRole::Member => "member",
        SpaceRole::Developer => "developer",
        SpaceRole::Admin => "admin",
    }
}

fn view(row: &vos::IngressAccessGrant) -> AccessView {
    AccessView {
        credential_id: hex::encode(row.credential_id),
        subject: hex::encode(row.subject),
        role: role_name(row.role),
        expires_at: row.expires_at,
        revoked: row.revoked,
    }
}
