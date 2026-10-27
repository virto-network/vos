//! A node's fault under load (T5): its unit killed some seconds into the
//! load and started again later, on the same data, each instant written
//! to the run's `faults.json` so the report's polls and the drivers'
//! intervals can be read against it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::hosts;
use crate::inventory::{Host, Inventory, Role};
use crate::runs::Run;

/// How long a killed unit may take to be gone.
const GONE_S: u64 = 10;

/// Which node to kill, and when, in seconds from the load's start.
#[derive(Clone, Debug)]
pub struct Fault {
    pub node: String,
    pub kill_at_s: u64,
    pub restart_at_s: u64,
}

impl Fault {
    /// Refused unless `node` is a node host of `inventory` and the kill
    /// and the restart both fall within a load of `secs`, in that order.
    pub fn validate(&self, inventory: &Inventory, secs: u64) -> Result<(), String> {
        if !inventory
            .hosts
            .iter()
            .any(|host| host.name == self.node && host.role == Role::Node)
        {
            return Err(format!(
                "--kill {}: not a node host of the inventory",
                self.node
            ));
        }
        if !(self.kill_at_s < self.restart_at_s && self.restart_at_s < secs) {
            return Err(format!(
                "--kill-at-s {} and --restart-at-s {} must fall in order within the load's {secs} s",
                self.kill_at_s, self.restart_at_s
            ));
        }
        Ok(())
    }
}

/// The fault's instants, in ms since the epoch.
#[derive(Debug, Default, Serialize)]
pub struct Record {
    pub node: String,
    /// When the coordinator started the drivers: the offsets' origin.
    pub start_ms: u64,
    pub kill_ms: u64,
    /// When the unit was seen gone.
    pub gone_ms: u64,
    pub restart_ms: u64,
    /// When the restarted node first answered with its key.
    pub answered_ms: u64,
}

/// The script that kills `unit` outright (SIGKILL, no shutdown) and waits
/// for it to be gone; it fails if it still runs after [`GONE_S`].
pub fn kill_script(unit: &str) -> String {
    let unit = hosts::quote(unit);
    format!(
        "systemctl --user kill --signal=SIGKILL {unit}\n\
         for _ in $(seq 1 {}); do\n\
         \x20 systemctl --user is-active --quiet {unit} || exit 0\n\
         \x20 sleep 0.1\n\
         done\n\
         echo {unit}' still runs' >&2\n\
         exit 1\n",
        GONE_S * 10
    )
}

/// Sleep until `at`, or return false when `stop` is set first.
fn until(at: Instant, stop: &AtomicBool) -> bool {
    while Instant::now() < at {
        if stop.load(Ordering::Relaxed) || hosts::interrupted() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// Kill `fault.node`'s unit `kill_at_s` after now and start it again at
/// `restart_at_s`, writing the instants to the run's `faults.json`. A
/// `stop` before the kill does nothing; before the restart, the node is
/// still restarted, so the run ends with every node up.
pub fn inject(
    inventory: &Inventory,
    run: &Run,
    fault: &Fault,
    stop: &AtomicBool,
) -> Result<(), String> {
    let host: &Host = inventory
        .nodes()
        .into_iter()
        .find(|host| host.name == fault.node)
        .ok_or_else(|| format!("{}: not a node host", fault.node))?;
    let start = Instant::now();
    let mut record = Record {
        node: host.name.clone(),
        start_ms: crate::now_ms(),
        ..Record::default()
    };
    if !until(start + Duration::from_secs(fault.kill_at_s), stop) {
        return Ok(());
    }
    record.kill_ms = crate::now_ms();
    hosts::run(host, &kill_script(&host.unit("node")))?;
    record.gone_ms = crate::now_ms();
    eprintln!("{}: node killed", host.name);
    until(start + Duration::from_secs(fault.restart_at_s), stop);
    record.restart_ms = crate::now_ms();
    crate::nodes::restart(inventory, run, host)?;
    record.answered_ms = crate::now_ms();
    eprintln!(
        "{}: node restarted, answering {} ms after its start",
        host.name,
        record.answered_ms - record.restart_ms
    );
    std::fs::write(
        run.file("faults.json"),
        serde_json::to_string_pretty(&record).expect("json"),
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::kill_script;

    /// The kill waits for the unit to be gone, and fails when it is not.
    #[test]
    fn a_kill_waits_for_the_unit_to_go() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        // A `systemctl` keeping each unit's state in a file: `kill` with
        // SIGKILL ends any unit but `stuck`.
        let systemctl = dir.path().join("systemctl");
        std::fs::write(
            &systemctl,
            format!(
                "#!/bin/bash\nshift\nverb=$1; shift\nstate={}\n\
                 case $verb in\n\
                 kill) [ \"$1\" = --signal=SIGKILL ] || exit 2\n\
                 \x20 [ \"$2\" = stuck ] || rm -f \"$state/$2\";;\n\
                 is-active) [ \"$(cat \"$state/$2\" 2>/dev/null)\" = active ];;\n\
                 esac\n",
                state.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            dir.path().display(),
            std::env::var("PATH").unwrap()
        );
        let kill = |unit: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(kill_script(unit))
                .env("PATH", &path)
                .status()
                .unwrap()
                .success()
        };
        for unit in ["node", "stuck"] {
            std::fs::write(state.join(unit), "active").unwrap();
        }
        assert!(kill("node"));
        assert!(!state.join("node").exists());
        assert!(!kill("stuck"), "a unit that outlives the kill fails it");
    }
}
