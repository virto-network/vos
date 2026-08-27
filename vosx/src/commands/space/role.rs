//! Manage capability roles in the canonical space authority.

use clap::Subcommand;
use serde::Serialize;
use vos::{Decode, Encode};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Subcommand, Debug)]
pub enum RoleCommand {
    /// List role definitions and member assignments.
    List,
    /// Create or replace a named capability role.
    Define {
        name: String,
        #[arg(long)]
        power: u16,
        /// Stable capability name. Repeat to build the role's set.
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
        /// Stable retry key. Never reuse it for different work.
        #[arg(long)]
        operation_key: String,
    },
    /// Delete a role definition. Existing assignments become ineffective.
    Delete {
        name: String,
        /// Stable retry key. Never reuse it for different work.
        #[arg(long)]
        operation_key: String,
    },
    /// Replace one member's complete role set.
    Grant {
        /// `me`, a libp2p PeerId, or a 64-character member SubjectId.
        member: String,
        #[arg(long = "role", required = true)]
        roles: Vec<String>,
        /// Stable retry key. Never reuse it for different work.
        #[arg(long)]
        operation_key: String,
    },
    /// Revoke every role assigned to one member.
    Revoke {
        /// `me`, a libp2p PeerId, or a 64-character member SubjectId.
        member: String,
        /// Stable retry key. Never reuse it for different work.
        #[arg(long)]
        operation_key: String,
    },
}

pub struct Args {
    pub space: String,
    pub command: Option<RoleCommand>,
}

#[derive(Serialize)]
struct RoleView {
    id: String,
    name: String,
    power: u16,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct AssignmentView {
    subject: String,
    grantor: String,
    roles: Vec<String>,
    epoch: u64,
    revoked: bool,
}

#[derive(Serialize)]
struct RoleStateView {
    roles: Vec<RoleView>,
    assignments: Vec<AssignmentView>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    match args.command.unwrap_or(RoleCommand::List) {
        RoleCommand::List => list(&args.space),
        RoleCommand::Define {
            name,
            power,
            capabilities,
            operation_key,
        } => define(&args.space, &name, power, &capabilities, &operation_key),
        RoleCommand::Delete {
            name,
            operation_key,
        } => delete(&args.space, &name, &operation_key),
        RoleCommand::Grant {
            member,
            roles,
            operation_key,
        } => grant(&args.space, &member, &roles, &operation_key),
        RoleCommand::Revoke {
            member,
            operation_key,
        } => revoke(&args.space, &member, &operation_key),
    }
}

fn authority(client: &DaemonClient) -> anyhow::Result<vos::actors::context::ServiceId> {
    client.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)
}

fn catalogue(
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

fn assignments(
    client: &DaemonClient,
    target: vos::actors::context::ServiceId,
) -> anyhow::Result<Vec<vos::SpaceMemberRoles>> {
    let mut after = Vec::new();
    let mut assignments = Vec::new();
    loop {
        let value = client.invoke_dyn(
            target,
            &vos::value::Msg::new("list_member_roles")
                .with("after", after.clone())
                .with("budget", 128u32),
        )?;
        let bytes = value
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("authority returned invalid member roles"))?;
        let page = Vec::<vos::SpaceMemberRoles>::try_decode(bytes)
            .ok_or_else(|| anyhow::anyhow!("decode authority member roles"))?;
        let Some(last) = page.last() else {
            break;
        };
        after = last.subject.to_vec();
        let done = page.len() < 128;
        assignments.extend(page);
        if done {
            break;
        }
    }
    Ok(assignments)
}

fn list(space: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let target = authority(client)?;
        let roles = catalogue(client, target)?;
        let assignments = assignments(client, target)?;
        let role_name = |id: &[u8; 32]| {
            roles
                .iter()
                .find(|role| &role.id == id)
                .map(|role| role.name.clone())
                .unwrap_or_else(|| format!("{}…", hex::encode(&id[..4])))
        };
        let view = RoleStateView {
            roles: roles
                .iter()
                .map(|role| RoleView {
                    id: hex::encode(role.id),
                    name: role.name.clone(),
                    power: role.power,
                    capabilities: role.capability_names.clone(),
                })
                .collect(),
            assignments: assignments
                .iter()
                .map(|row| AssignmentView {
                    subject: hex::encode(row.subject),
                    grantor: hex::encode(row.grantor),
                    roles: row.roles.iter().map(role_name).collect(),
                    epoch: row.epoch,
                    revoked: row.revoked,
                })
                .collect(),
        };
        if output::is_json() {
            output::print_json(&view);
        } else {
            println!("ROLES");
            for role in &view.roles {
                println!(
                    "  {:<16} power={:<5} {}",
                    role.name,
                    role.power,
                    role.capabilities.join(", ")
                );
            }
            println!("\nMEMBERS");
            if view.assignments.is_empty() {
                println!("  no explicit member assignments");
            } else {
                for row in &view.assignments {
                    println!(
                        "  {}  {}{}",
                        &row.subject[..12],
                        row.roles.join(", "),
                        if row.revoked { " (revoked)" } else { "" }
                    );
                }
            }
        }
        Ok(())
    })
}

fn define(
    space: &str,
    name: &str,
    power: u16,
    names: &[String],
    operation_key: &str,
) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let space_id = client
            .entry
            .id_bytes()
            .map(vos::service::SpaceId)
            .ok_or_else(|| anyhow::anyhow!("space ID is not canonical hex"))?;
        let target = authority(client)?;
        let mut pairs: Vec<_> = names
            .iter()
            .map(|name| (vos::CapabilityId::named(name).0, name.clone()))
            .collect();
        pairs.sort_unstable_by_key(|(id, _)| *id);
        pairs.dedup_by_key(|(id, _)| *id);
        let (capabilities, capability_names) = pairs.into_iter().unzip();
        let definition = vos::SpaceRoleDefinition {
            id: vos::RoleId::named(space_id, name).0,
            name: name.into(),
            power,
            capabilities,
            capability_names,
        };
        let message = vos::value::Msg::new("put_role").with("definition", definition.encode());
        if client
            .invoke_dyn_idempotent(target, &message, operation_key)?
            .as_bool()
            != Some(true)
        {
            anyhow::bail!("authority refused role definition");
        }
        if output::is_json() {
            output::print_json(&RoleView {
                id: hex::encode(definition.id),
                name: definition.name,
                power: definition.power,
                capabilities: definition.capability_names,
            });
        } else {
            println!("defined role '{name}'");
        }
        Ok(())
    })
}

fn delete(space: &str, name: &str, operation_key: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let target = authority(client)?;
        let role = catalogue(client, target)?
            .into_iter()
            .find(|role| role.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| anyhow::anyhow!("unknown role '{name}'"))?;
        let message = vos::value::Msg::new("delete_role").with("role", role.id.to_vec());
        if client
            .invoke_dyn_idempotent(target, &message, operation_key)?
            .as_bool()
            != Some(true)
        {
            anyhow::bail!("authority refused role deletion");
        }
        println!("deleted role '{}'", role.name);
        Ok(())
    })
}

fn grant(
    space: &str,
    member: &str,
    role_names: &[String],
    operation_key: &str,
) -> anyhow::Result<()> {
    let subject = resolve_subject(member)?;
    DaemonClient::with_connect(space, |client| {
        let target = authority(client)?;
        let catalogue = catalogue(client, target)?;
        let mut role_ids = Vec::new();
        for name in role_names {
            role_ids.push(
                catalogue
                    .iter()
                    .find(|role| role.name.eq_ignore_ascii_case(name))
                    .ok_or_else(|| anyhow::anyhow!("unknown role '{name}'"))?
                    .id,
            );
        }
        role_ids.sort_unstable();
        role_ids.dedup();
        let encoded = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(&role_ids)
            .map_err(|_| anyhow::anyhow!("encode member roles"))?;
        let message = vos::value::Msg::new("set_member_roles")
            .with("subject", subject.to_vec())
            .with("roles", vos::value::Value::Bytes(encoded.to_vec()));
        if client
            .invoke_dyn_idempotent(target, &message, operation_key)?
            .as_bool()
            != Some(true)
        {
            anyhow::bail!("authority refused member role assignment");
        }
        println!(
            "assigned {} to {}",
            role_names.join(", "),
            hex::encode(subject)
        );
        Ok(())
    })
}

fn revoke(space: &str, member: &str, operation_key: &str) -> anyhow::Result<()> {
    let subject = resolve_subject(member)?;
    DaemonClient::with_connect(space, |client| {
        let target = authority(client)?;
        let message = vos::value::Msg::new("revoke_member_roles").with("subject", subject.to_vec());
        if client
            .invoke_dyn_idempotent(target, &message, operation_key)?
            .as_bool()
            != Some(true)
        {
            anyhow::bail!("authority refused member role revocation");
        }
        println!("revoked roles for {}", hex::encode(subject));
        Ok(())
    })
}

fn resolve_subject(value: &str) -> anyhow::Result<[u8; 32]> {
    if value.len() == 64 {
        let bytes =
            hex::decode(value).map_err(|_| anyhow::anyhow!("member subject must be hex"))?;
        return <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("member subject must be exactly 32 bytes"));
    }
    let peer = if value == "me" {
        libp2p::PeerId::from(crate::identity::load_or_create()?.public())
    } else {
        value
            .parse::<libp2p::PeerId>()
            .map_err(|error| anyhow::anyhow!("parse peer '{value}': {error}"))?
    };
    Ok(vos::SubjectId::of_authenticated_peer(&peer.to_bytes()).0)
}
