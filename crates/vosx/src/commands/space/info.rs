//! `space info` — show metadata + daemon liveness for a single
//! space. When the daemon is up, also round-trips a registry
//! call to confirm reachability and report RTT (the diagnostic
//! the old `space ping` exposed).

use std::path::PathBuf;
use std::time::Instant;

use crate::commands::space::client::DaemonClient;
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
            // PID is alive but the libp2p path could still be
            // wedged (consensus hang, registry stuck). A real
            // round-trip is the only honest liveness check.
            print_rtt(query);
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

/// Connect to the daemon and time a single registry round-trip.
/// Prints `rtt` lines on success, or a one-line failure
/// explanation if the connect / invoke didn't go through.
/// Errors don't propagate — `info` is best-effort.
fn print_rtt(query: &str) {
    let connect_started = Instant::now();
    let client = match DaemonClient::connect(query) {
        Ok(c) => c,
        Err(e) => {
            println!("rtt         libp2p connect failed: {e}");
            return;
        }
    };
    let connected = connect_started.elapsed();
    let invoke_started = Instant::now();
    let outcome = client.programs();
    let invoke = invoke_started.elapsed();
    let _ = client.shutdown();
    match outcome {
        Ok(_) => println!("rtt         connect={connected:?}, invoke={invoke:?}"),
        Err(e) => println!("rtt         invoke failed (connect={connected:?}): {e}"),
    }
}
