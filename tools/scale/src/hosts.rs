//! Reaching a host: a shell script run there, files copied there and back
//! by `rsync`, and its user units. A `localhost` entry runs here, without
//! ssh; every other goes through `ssh` in batch mode, its keys already
//! installed.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::inventory::Host;

/// ssh's options: no prompt, a bounded connect, keep-alives.
const SSH: [&str; 6] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
];

/// The prelude of every script: strict, and the user's systemd manager
/// reachable from a non-interactive session.
const PRELUDE: &str =
    "set -euo pipefail\nexport XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/$(id -u)}\"\n";

/// The longest a script may run on a host before `timeout` ends it: a
/// hung host fails its command instead of the harness.
const SCRIPT_LIMIT_S: u64 = 300;

/// Set by SIGINT or SIGTERM once [`stop_on_interrupt`] installed its
/// handler: every wait ends with an error, so the run goes down.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupted_by(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Take SIGINT and SIGTERM as a request to stop: the harness's waits end,
/// and the caller stops its units.
pub fn stop_on_interrupt() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe.
        unsafe {
            libc::signal(signal, interrupted_by as *const () as libc::sighandler_t);
        }
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// A shell on `host` running `command`: here, or over ssh.
fn shell(host: &Host, command: &str) -> Command {
    if host.is_local() {
        let mut shell = Command::new("bash");
        shell.arg("-c").arg(command);
        shell
    } else {
        let mut shell = Command::new("ssh");
        shell.args(SSH).arg(&host.ssh).arg(command);
        shell
    }
}

/// `text` as one shell word.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Run `script` with bash on `host`: its stdout, or its stderr as the
/// error.
pub fn run(host: &Host, script: &str) -> Result<String, String> {
    let mut child = shell(host, &format!("timeout {SCRIPT_LIMIT_S} bash -s"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{}: {error}", host.name))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(format!("{PRELUDE}{script}").as_bytes())
        .map_err(|error| format!("{}: {error}", host.name))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("{}: {error}", host.name))?;
    if !output.status.success() {
        return Err(format!(
            "{}: {}",
            host.name,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Reads of `host`'s clock over one session, so no read pays a
/// connection's setup: for each, when it was asked (milliseconds since
/// the epoch, here), its round trip and the host's answer.
pub fn clock_reads(host: &Host, rounds: usize) -> Result<Vec<(f64, f64, f64)>, String> {
    let failed = |error: std::io::Error| format!("{}: {error}", host.name);
    let mut child = shell(
        host,
        "timeout 60 bash -c 'while read -r _; do date +%s%N; done'",
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(failed)?;
    let mut ask = child.stdin.take().expect("piped");
    let mut answers = BufReader::new(child.stdout.take().expect("piped"));
    let mut reads = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let sent = crate::precise_now_ms();
        let start = Instant::now();
        writeln!(ask).and_then(|()| ask.flush()).map_err(failed)?;
        let mut line = String::new();
        answers.read_line(&mut line).map_err(failed)?;
        let rtt = start.elapsed().as_secs_f64() * 1e3;
        let theirs =
            line.trim()
                .parse::<u128>()
                .map_err(|_| format!("{}: a clock of {line:?}", host.name))? as f64
                / 1e6;
        reads.push((sent, rtt, theirs));
    }
    drop(ask);
    let _ = child.wait();
    Ok(reads)
}

/// `rsync` with `args` before the source and destination.
fn rsync(args: &[&str], from: &str, to: &str, remote: bool) -> Result<(), String> {
    let mut command = Command::new("rsync");
    command.arg("-a").args(args);
    if remote {
        command.arg("-e").arg(format!("ssh {}", SSH.join(" ")));
    }
    let output = command
        .arg(from)
        .arg(to)
        .output()
        .map_err(|error| format!("rsync: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rsync {from} {to}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn at(host: &Host, path: &str) -> String {
    if host.is_local() {
        path.to_string()
    } else {
        format!("{}:{path}", host.ssh)
    }
}

/// Copy the local `from` to `to` on `host`.
pub fn push(host: &Host, from: &Path, to: &str) -> Result<(), String> {
    rsync(
        &[],
        &from.to_string_lossy(),
        &at(host, to),
        !host.is_local(),
    )
}

/// Copy `from` on `host` to the local `to`; a missing source copies
/// nothing.
pub fn pull(host: &Host, from: &str, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|error| format!("{}: {error}", to.display()))?;
    rsync(
        &["--ignore-missing-args"],
        &at(host, from),
        &format!("{}/", to.display()),
        !host.is_local(),
    )
}

/// A transient user unit: what `systemd-run --user` starts, its process
/// tracked by the unit, never by its name.
pub struct Unit<'a> {
    pub name: String,
    pub memory_max: &'a str,
    /// Where its stdout and stderr go, appended to.
    pub stdout: String,
    pub stderr: String,
    pub cores: Option<&'a str>,
    pub env: Vec<(&'a str, String)>,
    pub command: Vec<String>,
    /// The longest it runs before systemd stops it.
    pub runtime_max_s: u64,
}

impl Unit<'_> {
    /// The script that starts it, refused if a unit of its name is
    /// active.
    pub fn start_script(&self) -> String {
        let mut words = vec![
            "systemd-run".to_string(),
            "--user".into(),
            "--quiet".into(),
            "--collect".into(),
            format!("--unit={}", self.name),
            format!("--property=MemoryMax={}", self.memory_max),
            "--property=MemorySwapMax=0".into(),
            format!("--property=RuntimeMaxSec={}", self.runtime_max_s),
            // A node's ingress and a driver's clients hold a socket each.
            "--property=LimitNOFILE=65536".into(),
            format!("--property=StandardOutput=append:{}", self.stdout),
            format!("--property=StandardError=append:{}", self.stderr),
        ];
        for (name, value) in &self.env {
            words.push(format!("--setenv={name}={value}"));
        }
        if let Some(cores) = self.cores {
            words.extend(["taskset".into(), "-c".into(), cores.to_string()]);
        }
        words.extend(self.command.iter().cloned());
        let words: Vec<String> = words.iter().map(|word| quote(word)).collect();
        format!(
            "if systemctl --user is-active --quiet {name}; then echo '{name} is running: down first' >&2; exit 1; fi\n\
             systemctl --user reset-failed {name} 2>/dev/null || true\n{}\n",
            words.join(" "),
            name = quote(&self.name),
        )
    }
}

/// The script that stops `units`, each by its unit, and forgets them.
pub fn stop_script(units: &[String]) -> String {
    let names: Vec<String> = units.iter().map(|unit| quote(unit)).collect();
    let names = names.join(" ");
    format!(
        "systemctl --user stop {names} 2>/dev/null || true\nsystemctl --user reset-failed {names} 2>/dev/null || true\n"
    )
}

/// The script that prints whether `unit` is active: `active`, or what
/// it is instead.
pub fn state_script(unit: &str) -> String {
    format!(
        "systemctl --user is-active {} 2>/dev/null || true\n",
        quote(unit)
    )
}

/// Wait up to `limit` for `done`, every `every`.
pub fn wait_for(
    what: &str,
    limit: Duration,
    every: Duration,
    mut done: impl FnMut() -> Result<bool, String>,
) -> Result<(), String> {
    let start = Instant::now();
    loop {
        if interrupted() {
            return Err(format!("{what}: interrupted"));
        }
        if done()? {
            return Ok(());
        }
        if start.elapsed() > limit {
            return Err(format!("{what}: not within {} s", limit.as_secs()));
        }
        std::thread::sleep(every);
    }
}

#[cfg(test)]
mod tests {
    use super::{Unit, quote, stop_script};

    #[test]
    fn a_word_is_quoted_whole() {
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn a_unit_starts_under_its_cap_and_stops_by_its_name() {
        let unit = Unit {
            name: "vos-scale-node-a".into(),
            memory_max: "4G",
            stdout: "/d/logs/node.out".into(),
            stderr: "/d/logs/node.log".into(),
            cores: Some("0-3"),
            env: vec![("VOS_LOG", "info".into())],
            command: vec!["/d/bin/vos".into(), "node".into(), "run".into()],
            runtime_max_s: 3_600,
        };
        let script = unit.start_script();
        assert!(script.contains("'--unit=vos-scale-node-a'"));
        assert!(script.contains("'--property=MemoryMax=4G'"));
        assert!(script.contains("'--property=RuntimeMaxSec=3600'"));
        assert!(script.contains("'taskset' '-c' '0-3' '/d/bin/vos' 'node' 'run'"));
        assert!(script.contains("is-active --quiet 'vos-scale-node-a'"));
        let stop = stop_script(&["vos-scale-node-a".into()]);
        assert!(stop.starts_with("systemctl --user stop 'vos-scale-node-a'"));
        for script in [script, stop] {
            assert!(!script.contains("pkill") && !script.contains("killall"));
        }
    }
}
