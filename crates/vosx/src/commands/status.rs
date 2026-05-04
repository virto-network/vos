//! `vosx ps [<manifest>]` — live cluster status from the
//! operator's seat. Joins the manifest's hyperspace as a
//! transient peer (same model as `vosx call`), then prints:
//!
//! - this CLI's libp2p identity, prefix, and listen addresses
//! - every peer that has completed Hello, with its prefix
//! - a registry summary: total entries, unique roles, oldest /
//!   newest `last_seen` ages
//! - one row per registered service, table-formatted
//! - per-Raft-group cluster state: each peer's role, term,
//!   commit_index, last_log_index, leader_hint
//!
//! The Raft block uses the [`Frame::RaftStatusReq`] RPC: for
//! every Raft agent in the manifest, the operator sends a
//! status query to every connected peer and tabulates the
//! replies. Peers that don't host a given group return
//! `present = false` and are skipped from the table.

use std::path::Path;
use std::time::Duration;

use vos::abi::service::ServiceId;

use crate::manifest::{ConsistencyDef, Manifest, resolve_replication_id};
use crate::query::with_query_node;
use crate::util::{die, hex32, load_blob};

pub fn run(manifest: &Manifest, dir: &Path, connect: &[String], sync_timeout: u64) {
    with_query_node(manifest, dir, connect, sync_timeout, |node| {
        print_local_identity(node);
        print_peers(node);
        print_registry(node);
        print_raft_groups(manifest, dir, node);
    });
}

fn print_local_identity(node: &vos::node::VosNode) {
    let Some(net) = node.network() else {
        println!("local: (no network attached)");
        return;
    };
    println!("local:");
    println!("  peer_id: {}", net.peer_id());
    println!("  prefix:  {:#06x}", net.local_prefix());
    let listen = net.listen_addrs();
    if listen.is_empty() {
        println!("  listen:  (no bound addresses)");
    } else {
        println!("  listen:");
        for addr in listen {
            println!("    {addr}");
        }
    }
}

fn print_peers(node: &vos::node::VosNode) {
    let Some(net) = node.network() else { return };
    let peers = net.peers_with_prefixes();
    println!();
    if peers.is_empty() {
        println!("peers: (none connected)");
        return;
    }
    println!("peers ({}):", peers.len());
    let mut peers = peers;
    peers.sort_by_key(|(prefix, _)| *prefix);
    for (prefix, peer_id) in peers {
        println!("  {prefix:#06x}  {peer_id}");
    }
}

fn print_registry(node: &vos::node::VosNode) {
    println!();
    let client = registry::RegistryClient::at(node, ServiceId::REGISTRY);
    let page = client
        .list(String::new(), String::new(), 256)
        .unwrap_or_else(|e| die(&format!("registry list: {e}")));
    if page.entries.is_empty() {
        println!("registry: (empty) clock={}", page.clock);
        return;
    }
    println!("registry: {} entries  clock={}", page.entries.len(), page.clock);

    // Roles histogram + age range.
    let mut role_counts = std::collections::BTreeMap::<&str, usize>::new();
    let (mut oldest, mut newest) = (u64::MAX, 0u64);
    for entry in &page.entries {
        for r in &entry.roles {
            *role_counts.entry(r.as_str()).or_default() += 1;
        }
        oldest = oldest.min(entry.last_seen);
        newest = newest.max(entry.last_seen);
    }
    if !role_counts.is_empty() {
        let summary: Vec<String> = role_counts
            .iter()
            .map(|(role, n)| format!("{role}={n}"))
            .collect();
        println!("  roles: {}", summary.join(", "));
    }
    println!(
        "  ages:  newest={} oldest={} (clock - last_seen)",
        page.clock.saturating_sub(newest),
        page.clock.saturating_sub(oldest),
    );

    println!();
    let mut entries = page.entries;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let name_w = entries.iter().map(|e| e.name.len()).max().unwrap_or(8).max(8);
    println!("  {:<width$}  {:<14}  {:<6}  {}", "NAME", "SERVICE", "AGE", "ROLES",
        width = name_w);
    for entry in entries {
        let id = ServiceId(entry.full_service_id());
        let age = page.clock.saturating_sub(entry.last_seen);
        let roles = if entry.roles.is_empty() {
            "-".to_string()
        } else {
            entry.roles.join(",")
        };
        println!(
            "  {:<width$}  {id:<14}  {age:<6}  {roles}",
            entry.name,
            width = name_w,
        );
    }
}

/// One row per (peer, raft-group). Sends a `RaftStatusReq` to
/// every connected peer for every Raft agent in the manifest;
/// peers that don't host a given group are filtered out. Self
/// is included as a placeholder row so the operator sees that
/// the transient peer doesn't itself host any groups.
fn print_raft_groups(manifest: &Manifest, dir: &Path, node: &vos::node::VosNode) {
    let raft_agents: Vec<_> = manifest
        .agent
        .iter()
        .filter(|a| a.consistency == ConsistencyDef::Raft)
        .collect();
    if raft_agents.is_empty() {
        return;
    }
    let Some(net) = node.network() else { return };
    println!();
    println!("raft groups ({}):", raft_agents.len());
    let peers = net.peers_with_prefixes();
    if peers.is_empty() {
        println!("  (no peers connected — start more replicas with `vosx up` / `vosx join`)");
        return;
    }

    for agent in &raft_agents {
        let path = crate::manifest::resolve_entry_path(&agent.name, &agent.path, &agent.service, dir);
        let blob = load_blob(&path);
        let Some(rep_id) = resolve_replication_id(&agent.name, agent.replication_id.as_deref(), &blob) else {
            println!("  {}: replication_id = off (skipped)", agent.name);
            continue;
        };
        println!();
        println!("  {} (rep_id={}):", agent.name, hex32(&rep_id));
        println!(
            "    {:<8}  {:<10}  {:<6}  {:<8}  {:<8}  {}",
            "PEER", "ROLE", "TERM", "COMMIT", "LAST", "LEADER",
        );
        // Fan-out: send a status req to every peer in parallel,
        // then collect within a small deadline. This is two-phase
        // so a slow peer doesn't serialize the others.
        let receivers: Vec<_> = peers
            .iter()
            .map(|(prefix, peer_id)| (*prefix, net.send_raft_status_req(*peer_id, rep_id)))
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut rows: Vec<(u16, vos::network::RaftStatusReply)> = Vec::new();
        for (prefix, rx) in receivers {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { break; }
            if let Ok(reply) = rx.recv_timeout(remaining) {
                if reply.present {
                    rows.push((prefix, reply));
                }
            }
        }
        if rows.is_empty() {
            println!("    (no peers reported hosting this group)");
            continue;
        }
        rows.sort_by_key(|(p, _)| *p);
        for (prefix, reply) in rows {
            let leader = reply
                .leader_hint
                .map(|p| format!("{p:#06x}"))
                .unwrap_or_else(|| "-".into());
            println!(
                "    {:<#08x}  {:<10}  {:<6}  {:<8}  {:<8}  {leader}",
                prefix,
                reply.role.label(),
                reply.current_term,
                reply.commit_index,
                reply.last_log_index,
            );
        }
    }
}
