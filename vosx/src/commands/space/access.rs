//! Manage authority-owned access credentials for built-in ingress adapters.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use serde::Serialize;
use vos::Decode;

use super::client::DaemonClient;

#[derive(Subcommand, Debug)]
pub enum AccessCommand {
    /// Issue a bearer token for a stable space member. The secret is
    /// displayed once. Omit `--subject` to add a credential for yourself.
    Issue {
        /// Hex-encoded member SubjectId. Requires credential-management
        /// authority when it differs from the caller.
        #[arg(long)]
        subject: Option<String>,
        /// `24h`, `7d`, `30m`, `90s`, or bare seconds.
        #[arg(long, default_value = "24h")]
        expires: String,
    },
    /// Register an OpenSSH public key as another credential for a member.
    IssueSsh {
        /// Path to an OpenSSH public key (for example `~/.ssh/id_ed25519.pub`).
        public_key: PathBuf,
        /// Hex-encoded member SubjectId. Omit to add the key for yourself.
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value = "30d")]
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
    recovery_file: String,
    credential_id: String,
    subject: String,
    roles: Vec<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct AccessView {
    credential_id: String,
    subject: String,
    roles: Vec<String>,
    expires_at: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct IssuedSshAccess {
    credential_id: String,
    subject: String,
    roles: Vec<String>,
    expires_at: u64,
    public_key: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        AccessCommand::Issue { subject, expires } => {
            issue(&args.space, subject.as_deref(), &expires)
        }
        AccessCommand::IssueSsh {
            public_key,
            subject,
            expires,
        } => issue_ssh(&args.space, &public_key, subject.as_deref(), &expires),
        AccessCommand::List => list(&args.space),
        AccessCommand::Revoke { credential } => revoke(&args.space, &credential),
    }
}

fn issue(space: &str, subject: Option<&str>, expires: &str) -> anyhow::Result<()> {
    let ttl = crate::token::parse_duration(expires)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_at = now
        .checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("access expiry overflows Unix time"))?;
    let mut secret = [0_u8; 32];
    getrandom::getrandom(&mut secret)?;
    let credential_id = vos::ingress_credential_id(&secret);
    let token = vos::ingress::encode_access_token(&secret);
    let recovery_file = persist_recovery_token(space, &credential_id, &token)?;
    DaemonClient::with_connect(space, |client| {
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let catalogue = role_catalog(client, target)?;
        let subject = match subject {
            Some(value) => {
                let bytes =
                    hex::decode(value).map_err(|_| anyhow::anyhow!("subject must be hex"))?;
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow::anyhow!("subject must be exactly 32 bytes"))?
            }
            None => [0; 32],
        };
        let message = vos::value::Msg::new("issue_access")
            .with("credential_id", credential_id.to_vec())
            .with("subject", subject.to_vec())
            .with("expires_at", expires_at);
        let operation_key = format!("issue-access:{}", hex::encode(credential_id));
        let value = client.invoke_dyn_idempotent(target, &message, &operation_key)?;
        let bytes = value
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("authority returned an invalid access decision"))?;
        let status = vos::IngressAccessStatus::try_decode(bytes)
            .ok_or_else(|| anyhow::anyhow!("authority refused access issuance"))?;
        if status.credential_id != credential_id {
            anyhow::bail!("authority returned a mismatched credential");
        }
        let view = IssuedAccess {
            token,
            recovery_file: recovery_file.display().to_string(),
            credential_id: hex::encode(credential_id),
            subject: hex::encode(status.subject),
            roles: role_names_for(&catalogue, &status.roles),
            expires_at: status.expires_at,
        };
        if crate::output::is_json() {
            crate::output::print_json(&view);
        } else {
            println!("{}", view.token);
            eprintln!("recovery    {}", view.recovery_file);
            eprintln!("credential  {}", view.credential_id);
            eprintln!("roles       {}", view.roles.join(", "));
            eprintln!("expires_at  {}", view.expires_at);
        }
        Ok(())
    })
}

fn issue_ssh(
    space: &str,
    public_key_path: &Path,
    subject: Option<&str>,
    expires: &str,
) -> anyhow::Result<()> {
    let encoded = std::fs::read_to_string(public_key_path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", public_key_path.display()))?;
    let public_key = ssh_key::PublicKey::from_openssh(encoded.trim())
        .map_err(|error| anyhow::anyhow!("parse {}: {error}", public_key_path.display()))?;
    let canonical = public_key
        .to_bytes()
        .map_err(|error| anyhow::anyhow!("encode SSH public key: {error}"))?;
    let credential_id = vos::ssh_credential_id(&canonical);
    let ttl = crate::token::parse_duration(expires)?;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("access expiry overflows Unix time"))?;
    let subject = match subject {
        Some(value) => {
            let bytes = hex::decode(value).map_err(|_| anyhow::anyhow!("subject must be hex"))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("subject must be exactly 32 bytes"))?
        }
        None => [0; 32],
    };
    DaemonClient::with_connect(space, |client| {
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let catalogue = role_catalog(client, target)?;
        let message = vos::value::Msg::new("issue_access")
            .with("credential_id", credential_id.to_vec())
            .with("subject", subject.to_vec())
            .with("expires_at", expires_at);
        let operation_key = format!("issue-ssh:{}", hex::encode(credential_id));
        let value = client.invoke_dyn_idempotent(target, &message, &operation_key)?;
        let bytes = value
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("authority returned an invalid access decision"))?;
        let status = vos::IngressAccessStatus::try_decode(bytes)
            .ok_or_else(|| anyhow::anyhow!("authority refused SSH access issuance"))?;
        if status.credential_id != credential_id {
            anyhow::bail!("authority returned a mismatched SSH credential");
        }
        let view = IssuedSshAccess {
            credential_id: hex::encode(status.credential_id),
            subject: hex::encode(status.subject),
            roles: role_names_for(&catalogue, &status.roles),
            expires_at: status.expires_at,
            public_key: public_key
                .to_openssh()
                .map_err(|error| anyhow::anyhow!("render SSH public key: {error}"))?,
        };
        if crate::output::is_json() {
            crate::output::print_json(&view);
        } else {
            println!("credential  {}", view.credential_id);
            println!("subject     {}", view.subject);
            println!("roles       {}", view.roles.join(", "));
            println!("expires_at  {}", view.expires_at);
            println!("public_key  {}", view.public_key);
        }
        Ok(())
    })
}

fn persist_recovery_token(
    space: &str,
    credential_id: &[u8; 32],
    token: &str,
) -> anyhow::Result<PathBuf> {
    let index = crate::spaces_index::load()?;
    let entry = crate::spaces_index::find(&index, space)?;
    let directory = Path::new(&entry.data_dir).join("private/access");
    std::fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let name = format!("{}.token", hex::encode(credential_id));
    let destination = directory.join(name);
    let temporary = directory.join(format!(
        ".access-{}-{}.tmp",
        std::process::id(),
        hex::encode(&credential_id[..8]),
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&temporary, &destination)?;
    std::fs::File::open(&directory)?.sync_all()?;
    Ok(destination)
}

fn list(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let catalogue = role_catalog(client, target)?;
        let rows = access_rows_for(client, target)?;
        let views: Vec<_> = rows
            .iter()
            .map(|row| view(client, target, row, &catalogue))
            .collect::<anyhow::Result<_>>()?;
        if crate::output::is_json() {
            crate::output::print_json(&views);
        } else if views.is_empty() {
            println!("no ingress access credentials");
        } else {
            println!(
                "{:<14}  {:<20}  {:<10}  SUBJECT",
                "CREDENTIAL", "ROLES", "STATUS"
            );
            for row in views {
                println!(
                    "{:<14}  {:<20}  {:<10}  {}",
                    &row.credential_id[..12],
                    row.roles.join(","),
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
        let target = client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        let rows = access_rows_for(client, target)?;
        let matches: Vec<_> = rows
            .iter()
            .filter(|row| hex::encode(row.credential_id).starts_with(selector))
            .collect();
        let row = match matches.as_slice() {
            [row] => *row,
            [] => anyhow::bail!("no credential matches '{selector}'"),
            _ => anyhow::bail!("credential prefix '{selector}' is ambiguous"),
        };
        let message =
            vos::value::Msg::new("revoke_access").with("credential_id", row.credential_id.to_vec());
        let operation_key = format!("revoke-access:{}", hex::encode(row.credential_id));
        if client
            .invoke_dyn_idempotent(target, &message, &operation_key)?
            .as_bool()
            != Some(true)
        {
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

fn access_rows_for(
    client: &DaemonClient,
    target: vos::actors::context::ServiceId,
) -> anyhow::Result<Vec<vos::IngressAccessGrant>> {
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
            .map(|row| row.credential_id.to_vec())
            .unwrap_or_default();
        rows.extend(page);
        if count < 128 {
            break;
        }
    }
    Ok(rows)
}

fn role_catalog(
    client: &DaemonClient,
    target: vos::actors::context::ServiceId,
) -> anyhow::Result<Vec<vos::SpaceRoleDefinition>> {
    let value = client.invoke_dyn(target, &vos::value::Msg::new("list_roles"))?;
    let bytes = value
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("authority returned an invalid role catalogue"))?;
    Vec::<vos::SpaceRoleDefinition>::try_decode(bytes)
        .ok_or_else(|| anyhow::anyhow!("decode authority role catalogue"))
}

fn role_names_for(catalogue: &[vos::SpaceRoleDefinition], roles: &[[u8; 32]]) -> Vec<String> {
    roles
        .iter()
        .map(|id| {
            catalogue
                .iter()
                .find(|role| role.id == *id)
                .map(|role| role.name.clone())
                .unwrap_or_else(|| format!("{}…", hex::encode(&id[..4])))
        })
        .collect()
}

fn view(
    client: &DaemonClient,
    target: vos::actors::context::ServiceId,
    row: &vos::IngressAccessGrant,
    catalogue: &[vos::SpaceRoleDefinition],
) -> anyhow::Result<AccessView> {
    let message = vos::value::Msg::new("authenticate_access")
        .with("credential_id", row.credential_id.to_vec());
    let value = client.invoke_dyn(target, &message)?;
    let status = value
        .as_bytes()
        .and_then(vos::IngressAccessStatus::try_decode);
    Ok(AccessView {
        credential_id: hex::encode(row.credential_id),
        subject: hex::encode(row.subject),
        roles: status
            .as_ref()
            .map(|status| role_names_for(catalogue, &status.roles))
            .unwrap_or_default(),
        expires_at: row.expires_at,
        revoked: row.revoked,
    })
}
