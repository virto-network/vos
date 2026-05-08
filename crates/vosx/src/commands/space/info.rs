//! `space info` — show metadata for a single space.

use std::path::PathBuf;

use crate::commands::space::endpoint;
use crate::commands::space::subscriptions;
use crate::spaces_index;

pub fn run(query: &str) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, query)?;

    println!("name        {}", entry.name);
    println!("space_id    {}", entry.id);
    println!("created_at  {}", entry.created_at);
    println!("data_dir    {}", entry.data_dir);

    let data_dir = PathBuf::from(&entry.data_dir);

    // Persisted listen prefs from local.toml (per-space user
    // setting; --listen on `space up` overrides per-run).
    let local_cfg = subscriptions::load(&data_dir).unwrap_or_default();
    if local_cfg.listen.is_empty() {
        println!("listen      (none — `space up --listen <addr>` per run, or set");
        println!("            `listen = [...]` in local.toml for a persistent default)");
    } else {
        println!("listen");
        for a in &local_cfg.listen {
            println!("  {a}");
        }
    }

    if !entry.bootnodes.is_empty() {
        println!("bootnodes");
        for b in &entry.bootnodes {
            println!("  {b}");
        }
    }

    if local_cfg.is_filtering() {
        println!("subscriptions ({})", local_cfg.subscriptions.len());
        for s in &local_cfg.subscriptions {
            println!("  {s}");
        }
    } else {
        println!("subscriptions  (none — syncing all installed agents)");
    }

    // Live endpoint info — only present while `space up` is
    // running, written to .endpoint on swarm bind, removed on
    // graceful shutdown.
    match endpoint::read(&data_dir)? {
        Some(ep) if endpoint::is_alive(&ep) => {
            println!();
            println!("daemon      RUNNING (pid {})", ep.pid);
            println!("peer_id     {}", ep.peer_id);
            for m in &ep.multiaddrs {
                println!("  {m}/p2p/{}", ep.peer_id);
            }
            if let Some(first) = ep.multiaddrs.first() {
                println!("bootnode hint:");
                println!("  {}@{first}/p2p/{}", entry.id, ep.peer_id);
            }
        }
        Some(ep) => {
            println!();
            println!("daemon      STALE endpoint (pid {} not running)", ep.pid);
        }
        None => {
            println!();
            println!("daemon      not running");
        }
    }

    let agents_dir = data_dir.join("agents");
    let count = match std::fs::read_dir(&agents_dir) {
        Ok(rd) => rd.flatten().count(),
        Err(_) => 0,
    };
    println!("agents      {count} on disk (in {})", agents_dir.display());

    Ok(())
}
