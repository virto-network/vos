//! `space raft-status` — the connected daemon's view of an agent's
//! Raft group: role, term, leader, and members.
//!
//! Keyed off the agent's `replication_id` (from the registry) and
//! answered by a `RaftStatusReq` frame to the daemon. Leader targeting
//! (which node to send Operator-gated writes to), the demo's kill/restart
//! beat, and the watch view all read this.

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::consistency_name;
use crate::output;
use vos::network::{RaftRole, RaftStatusReply};
use serde::Serialize;

const RAFT_CONSISTENCY: u8 = 3;

#[derive(Serialize)]
struct RaftStatusView {
    instance: String,
    replication_id: String,
    present: bool,
    role: &'static str,
    current_term: u64,
    commit_index: u64,
    last_log_index: u64,
    leader: Option<u16>,
    members: Vec<u16>,
    /// The prefix of the daemon that answered — so the reader can tell
    /// which node's view this is (and whether it is itself the leader).
    daemon_prefix: u16,
}

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        let Some(agent) = client.agent(instance)? else {
            anyhow::bail!(
                "no agent '{instance}' in space '{space}'. \
                 List installed agents with `vosx space agents {space}`."
            );
        };
        if agent.consistency != RAFT_CONSISTENCY {
            anyhow::bail!(
                "agent '{instance}' is {} consistency, not raft — no Raft group to report",
                consistency_name(agent.consistency),
            );
        }

        let reply = client.raft_status(agent.replication_id)?;
        let daemon_prefix = client.daemon_prefix();

        if output::is_json() {
            output::print_json(&RaftStatusView {
                instance: instance.to_string(),
                replication_id: hex::encode(agent.replication_id),
                present: reply.present,
                role: role_label(reply.role),
                current_term: reply.current_term,
                commit_index: reply.commit_index,
                last_log_index: reply.last_log_index,
                leader: reply.leader_hint,
                members: reply.members.clone(),
                daemon_prefix,
            });
            return Ok(());
        }

        print_text(instance, daemon_prefix, &reply);
        Ok(())
    })
}

fn print_text(instance: &str, daemon_prefix: u16, reply: &RaftStatusReply) {
    if !reply.present {
        println!(
            "{instance}: daemon (node {daemon_prefix:#06x}) is not running this Raft group"
        );
        return;
    }
    println!("agent      {instance}");
    println!("node       {daemon_prefix:#06x} (the daemon answering)");
    println!("role       {}", role_label(reply.role));
    println!("term       {}", reply.current_term);
    println!(
        "log        commit={} last={}",
        reply.commit_index, reply.last_log_index
    );
    match reply.leader_hint {
        Some(p) => {
            let here = if p == daemon_prefix { " (this node)" } else { "" };
            println!("leader     {p:#06x}{here}");
        }
        None => println!("leader     unknown (election in flight)"),
    }
    if reply.members.is_empty() {
        println!("members    (none reported)");
    } else {
        let rendered: Vec<String> = reply
            .members
            .iter()
            .map(|&p| {
                let mut tag = String::new();
                if Some(p) == reply.leader_hint {
                    tag.push_str(" leader");
                }
                if p == daemon_prefix {
                    tag.push_str(" self");
                }
                format!("{p:#06x}{tag}")
            })
            .collect();
        println!("members    {}", rendered.join(", "));
    }
}

fn role_label(role: RaftRole) -> &'static str {
    match role {
        RaftRole::Follower => "follower",
        RaftRole::PreCandidate => "pre-candidate",
        RaftRole::Candidate => "candidate",
        RaftRole::Leader => "leader",
        RaftRole::Unknown(_) => "unknown",
    }
}
