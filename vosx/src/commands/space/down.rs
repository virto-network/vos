//! `space down` — graceful shutdown of a running `space up`
//! daemon by SIGTERM-ing its recorded PID.
//!
//! The daemon already cleans up on SIGTERM: it drops listen
//! sockets, removes its `.endpoint` file, persists the registry,
//! and lets agents flush state before exiting. Sending a signal
//! is faster than encoding a "shutdown" RPC and means we don't
//! have to introduce a new wire frame just for this.
//!
//! `--force` upgrades to SIGKILL when the daemon refuses to
//! exit within the grace window (default: 5 seconds). The grace
//! window covers a daemon that's mid-commit on a slow disk;
//! once persistence drains, it exits on its own.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::commands::space::endpoint;
use crate::spaces_index;

pub struct Args {
    pub query: String,
    pub force: bool,
    pub grace_secs: u64,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.query)?;
    let data_dir = PathBuf::from(&entry.data_dir);

    let ep = endpoint::read(&data_dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no daemon running for space '{}' (no endpoint file).",
            entry.name,
        )
    })?;

    if !endpoint::is_alive(&ep) {
        endpoint::delete(&data_dir);
        println!(
            "no daemon was running (cleaned up stale endpoint from pid {})",
            ep.pid,
        );
        return Ok(());
    }

    // SIGTERM first. The daemon's signal handler is the same
    // path Ctrl-C takes — registry persists, sockets close,
    // `.endpoint` removed.
    let sigterm = unsafe { libc::kill(ep.pid as libc::pid_t, libc::SIGTERM) };
    if sigterm != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("kill(SIGTERM, pid={}): {err}", ep.pid);
    }
    println!("sent SIGTERM to daemon pid {}", ep.pid);

    let grace = Duration::from_secs(args.grace_secs);
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !endpoint::is_alive(&ep) {
            // Daemon exited cleanly. Its own shutdown path removes
            // the endpoint file; if it didn't (crash mid-cleanup),
            // we sweep it ourselves.
            endpoint::delete(&data_dir);
            println!("daemon exited cleanly");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !args.force {
        anyhow::bail!(
            "daemon (pid {}) still running after {grace:?}. \
             Re-run with `--force` to SIGKILL.",
            ep.pid,
        );
    }

    let sigkill = unsafe { libc::kill(ep.pid as libc::pid_t, libc::SIGKILL) };
    if sigkill != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("kill(SIGKILL, pid={}): {err}", ep.pid);
    }
    // Best-effort cleanup — SIGKILL skips the daemon's own
    // unmount path.
    endpoint::delete(&data_dir);
    println!("daemon force-killed (pid {})", ep.pid);
    Ok(())
}
