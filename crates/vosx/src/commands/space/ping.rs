//! `space ping` — round-trip an empty registry query against
//! the running daemon, print "reachable" + RTT.
//!
//! Diagnostic for "is `space up` actually serving requests?".
//! Failure modes:
//! - No `.endpoint` file: daemon not running.
//! - Stale `.endpoint` (PID dead): leftover from a crash.
//! - Connect timeout: libp2p didn't complete the Hello
//!   handshake (network down / firewalled).
//! - Invoke timeout: daemon up, registry stuck (consensus
//!   hang, bug).

use std::time::Instant;

use crate::commands::space::client::DaemonClient;

pub fn run(space: &str) -> anyhow::Result<()> {
    let started = Instant::now();
    let client = DaemonClient::connect(space)?;
    let connected = started.elapsed();

    let invoke_start = Instant::now();
    let _ = client.programs()?;
    let invoke = invoke_start.elapsed();

    println!("daemon reachable for space '{}'", client.entry.name);
    println!("  connect (incl. libp2p Hello): {connected:?}");
    println!("  invoke (registry.programs):    {invoke:?}");
    client.shutdown()
}
