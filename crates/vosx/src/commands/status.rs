//! `vosx status [<manifest>]` — snapshot of a hyperspace from
//! the operator's seat. Joins the manifest's hyperspace as a
//! transient peer (same model as `vosx invoke`), then prints:
//!
//! - this CLI's libp2p identity, prefix, and listen addresses
//! - every peer that has completed Hello, with its prefix
//! - a registry summary: total entries, unique roles, oldest /
//!   newest `last_seen` ages
//! - the entries themselves, sorted alphabetically

use std::path::Path;

use vos::abi::service::ServiceId;

use crate::manifest::Manifest;
use crate::query::with_query_node;
use crate::util::die;

pub fn run(manifest: &Manifest, dir: &Path, connect: &[String], sync_timeout: u64) {
    with_query_node(manifest, dir, connect, sync_timeout, |node| {
        print_local_identity(node);
        print_peers(node);
        print_registry(node);
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
    for entry in entries {
        let id = ServiceId(entry.full_service_id());
        let age = page.clock.saturating_sub(entry.last_seen);
        let roles = if entry.roles.is_empty() {
            String::new()
        } else {
            format!(" {:?}", entry.roles)
        };
        println!(
            "  {} → {id} (age={age}){roles}",
            entry.name,
        );
    }
}
