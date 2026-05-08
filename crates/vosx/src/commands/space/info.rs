//! `space info` — show metadata + daemon liveness for a single
//! space. When the daemon is up, also round-trips a registry
//! call to confirm reachability and report RTT (the diagnostic
//! the old `space ping` exposed).

use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::endpoint::{self, Endpoint};
use crate::commands::space::subscriptions::{self, LocalConfig};
use crate::output;
use crate::spaces_index::{self, SpaceEntry};

#[derive(Serialize)]
struct InfoView<'a> {
    name: &'a str,
    space_id: &'a str,
    created_at: &'a str,
    data_dir: &'a str,
    listen: &'a [String],
    bootnodes: &'a [String],
    subscriptions: &'a [String],
    daemon: DaemonState,
    agents_on_disk: usize,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
enum DaemonState {
    Down,
    Stale {
        pid: u32,
    },
    Running {
        pid: u32,
        peer_id: String,
        multiaddrs: Vec<String>,
        rtt: Option<RttView>,
        rtt_error: Option<String>,
    },
}

#[derive(Serialize)]
struct RttView {
    connect_us: u128,
    invoke_us: u128,
}

pub fn run(query: &str) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, query)?;
    let data_dir = PathBuf::from(&entry.data_dir);
    let local_cfg = subscriptions::load(&data_dir).unwrap_or_default();

    if output::is_json() {
        let agents_on_disk = std::fs::read_dir(data_dir.join("agents"))
            .map(|rd| rd.flatten().count())
            .unwrap_or(0);
        let daemon = match endpoint::read(&data_dir)? {
            Some(ep) if endpoint::is_alive(&ep) => running_state(query, ep),
            Some(ep) => DaemonState::Stale { pid: ep.pid },
            None => DaemonState::Down,
        };
        let view = InfoView {
            name: &entry.name,
            space_id: &entry.id,
            created_at: &entry.created_at,
            data_dir: &entry.data_dir,
            listen: &local_cfg.listen,
            bootnodes: &entry.bootnodes,
            subscriptions: &local_cfg.subscriptions,
            daemon,
            agents_on_disk,
        };
        output::print_json(&view);
        return Ok(());
    }

    print_text(entry, &data_dir, &local_cfg, query)
}

fn print_text(
    entry: &SpaceEntry,
    data_dir: &std::path::Path,
    local_cfg: &LocalConfig,
    query: &str,
) -> anyhow::Result<()> {
    println!("name        {}", entry.name);
    println!("space_id    {}", entry.id);
    println!("created_at  {}", entry.created_at);
    println!("data_dir    {}", entry.data_dir);

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
    match endpoint::read(data_dir)? {
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

/// Connect to the daemon, time a registry round-trip, and pack
/// the outcome into the JSON `Running` variant. Errors are
/// surfaced via `rtt_error` rather than failing the whole call,
/// matching the text path's best-effort behavior.
fn running_state(query: &str, ep: Endpoint) -> DaemonState {
    let connect_started = Instant::now();
    let (rtt, rtt_error) = match DaemonClient::connect(query) {
        Ok(client) => {
            let connect_us = connect_started.elapsed().as_micros();
            let invoke_started = Instant::now();
            let outcome = client.programs();
            let invoke_us = invoke_started.elapsed().as_micros();
            let _ = client.shutdown();
            match outcome {
                Ok(_) => (Some(RttView { connect_us, invoke_us }), None),
                Err(e) => (None, Some(e.to_string())),
            }
        }
        Err(e) => (None, Some(e.to_string())),
    };
    DaemonState::Running {
        pid: ep.pid,
        peer_id: ep.peer_id,
        multiaddrs: ep.multiaddrs,
        rtt,
        rtt_error,
    }
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
