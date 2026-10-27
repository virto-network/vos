//! A watch on the waits of a test process: each wait a test makes is
//! registered while it lasts, with how long it may take. One that outlasts
//! its bound is a hang, and so, in a process that asks for it ([`idle`]),
//! is a long stretch with no wait pending and none begun or ended: a
//! thread stuck outside the waits, in its exit or in a join of another.
//! The watch writes every wait still pending, the last each thread ended,
//! each thread's state and, where `gdb` can attach, every thread's stack,
//! then aborts the process, so a hang fails fast and says where it is.
//!
//! `VOS_CHECKER_WATCH=off` turns the watch off (a test held in a debugger
//! waits as long as it is held), and `VOS_CHECKER_WATCH=nostacks` leaves
//! out the stacks.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// How long past its own deadline a wait may go before it counts as hung:
/// a loaded host may hold a thread for seconds, never for minutes.
pub const GRACE: Duration = Duration::from_secs(180);

/// How often the watch looks.
const EVERY: Duration = Duration::from_secs(1);

/// How long a stack dump may take before the watch aborts without it. A
/// `gdb` that hangs while attached holds the watch's thread too, so this
/// bounds only a `gdb` that never attaches.
const DUMP: Duration = Duration::from_secs(60);

/// What `VOS_CHECKER_WATCH` asks of the watch, read once.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    On,
    Off,
    NoStacks,
}

fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("VOS_CHECKER_WATCH").as_deref() {
        Ok("off") => Mode::Off,
        Ok("nostacks") => Mode::NoStacks,
        _ => Mode::On,
    })
}

/// A wait in progress: the thread making it, what it waits for, since
/// when, and for how long it may.
struct Wait {
    thread: String,
    what: String,
    since: Instant,
    bound: Duration,
}

/// The last wait each thread ended, and when: where a thread hung outside
/// any wait last was.
struct Ended {
    what: String,
    at: Instant,
}

struct Waits {
    pending: BTreeMap<u64, Wait>,
    ended: BTreeMap<String, Ended>,
    /// When a wait last began or ended.
    moved: Option<Instant>,
    /// How long the process may go with no wait pending and none moving.
    idle: Option<Duration>,
}

fn waits() -> std::sync::MutexGuard<'static, Waits> {
    static WAITS: Mutex<Waits> = Mutex::new(Waits {
        pending: BTreeMap::new(),
        ended: BTreeMap::new(),
        moved: None,
        idle: None,
    });
    WAITS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The watch's thread, started once.
fn start() {
    static WATCH: OnceLock<()> = OnceLock::new();
    WATCH.get_or_init(|| {
        std::thread::Builder::new()
            .name("vos-checker-watch".into())
            .spawn(watch)
            .expect("the watch starts");
    });
}

/// A wait registered with the watch while it lives.
#[must_use = "the wait is watched while this lives"]
pub struct Watched(u64);

impl Drop for Watched {
    fn drop(&mut self) {
        let mut waits = waits();
        if let Some(wait) = waits.pending.remove(&self.0) {
            let ended = Ended {
                what: wait.what,
                at: Instant::now(),
            };
            waits.ended.insert(wait.thread, ended);
            waits.moved = Some(Instant::now());
        }
    }
}

/// From now on, a hang too is `bound` with no wait pending and none begun
/// or ended: for a process whose every test waits through the watch.
pub fn idle(bound: Duration) {
    if mode() == Mode::Off {
        return;
    }
    start();
    let mut waits = waits();
    waits.idle = Some(waits.idle.map_or(bound, |idle| idle.max(bound)));
    waits.moved.get_or_insert_with(Instant::now);
}

/// Watch the current thread's wait for `what`, which ends within `within`
/// unless it hangs: past `within` and [`GRACE`], the process aborts.
pub fn waiting(what: impl Into<String>, within: Duration) -> Watched {
    watched(what.into(), within + GRACE)
}

/// Watch the current thread's wait for `what`: past `bound`, it hung.
fn watched(what: String, bound: Duration) -> Watched {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    if mode() == Mode::Off {
        return Watched(id);
    }
    start();
    let current = std::thread::current();
    let wait = Wait {
        thread: current
            .name()
            .map_or_else(|| format!("{:?}", current.id()), str::to_string),
        what,
        since: Instant::now(),
        bound,
    };
    let mut waits = waits();
    waits.pending.insert(id, wait);
    waits.moved = Some(Instant::now());
    Watched(id)
}

fn watch() {
    loop {
        std::thread::sleep(EVERY);
        if let Some(hang) = hang() {
            let mut report = format!("\nthe watch: {hang}: a hang\n");
            report.push_str(&pending());
            report.push_str(&threads());
            // Unbuffered and past any test's output capture.
            let _ = std::io::stderr().write_all(report.as_bytes());
            stacks();
            std::process::abort();
        }
    }
}

/// What hung, if anything: a wait past its bound, or the process idle
/// past its own.
fn hang() -> Option<String> {
    let waits = waits();
    if let Some(wait) = waits
        .pending
        .values()
        .find(|wait| wait.since.elapsed() > wait.bound)
    {
        return Some(format!(
            "`{}` waited past {}s for {}",
            wait.thread,
            wait.bound.as_secs(),
            wait.what
        ));
    }
    let idle = waits.idle?;
    let still = waits.moved?.elapsed();
    (waits.pending.is_empty() && still > idle).then(|| {
        format!(
            "no wait pending, and none begun or ended, for {}s",
            still.as_secs()
        )
    })
}

/// Every wait still pending, oldest first, and the last wait each thread
/// ended.
fn pending() -> String {
    let waits = waits();
    let mut report = String::from("waits pending:\n");
    let mut pending: Vec<&Wait> = waits.pending.values().collect();
    pending.sort_by_key(|wait| wait.since);
    for wait in pending {
        report.push_str(&format!(
            "  {}: {} ({}s of {}s)\n",
            wait.thread,
            wait.what,
            wait.since.elapsed().as_secs(),
            wait.bound.as_secs()
        ));
    }
    report.push_str("waits last ended:\n");
    for (thread, ended) in &waits.ended {
        report.push_str(&format!(
            "  {thread}: {}, {}s ago\n",
            ended.what,
            ended.at.elapsed().as_secs()
        ));
    }
    report
}

/// Each thread of the process: its name, its state and where in the
/// kernel it sleeps (a futex for a lock or a join, a poll for I/O).
fn threads() -> String {
    let mut report = String::from("threads (tid name state wchan):\n");
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return report;
    };
    for task in tasks.flatten() {
        let path = task.path();
        let read = |file: &str| {
            std::fs::read_to_string(path.join(file))
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        let stat = read("stat");
        // The state follows the name, which is in parentheses.
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split(' ').next())
            .unwrap_or("?")
            .to_string();
        report.push_str(&format!(
            "  {} {} {state} {}\n",
            task.file_name().to_string_lossy(),
            read("comm"),
            read("wchan")
        ));
    }
    report
}

/// Every thread's stack, by `gdb` attached to this process, where it is
/// installed and may attach: this process lets any process trace it, as
/// the watch's child is not its ancestor.
fn stacks() {
    if mode() == Mode::NoStacks {
        return;
    }
    // SAFETY: prctl with PR_SET_PTRACER changes only who may trace this
    // process.
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
    }
    let Ok(stderr) = std::io::stderr().as_fd().try_clone_to_owned() else {
        return;
    };
    let Ok(mut gdb) = std::process::Command::new("gdb")
        .args(["-p", &std::process::id().to_string(), "-batch", "-nx"])
        .args([
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "set pagination off",
        ])
        .args(["-ex", "thread apply all bt"])
        .stdin(std::process::Stdio::null())
        .stdout(stderr)
        .spawn()
    else {
        return;
    };
    let until = Instant::now() + DUMP;
    while Instant::now() < until {
        if let Ok(Some(_)) = gdb.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = gdb.kill();
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Output, Stdio};
    use std::sync::mpsc;

    use super::*;

    /// Set in the test binary run again as one hanging test alone.
    const CHILD: &str = "VOS_CHECKER_WATCH_CHILD";

    /// Whether this run is the hanging one.
    fn hanging() -> bool {
        std::env::var_os(CHILD).is_some()
    }

    /// Test `test` run alone in this binary again, as the hanging run:
    /// how it ended, once it did within a minute.
    fn run_alone(test: &str) -> Output {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("VOS_CHECKER_WATCH", "nostacks")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let id = child.id();
        let (sender, ended) = mpsc::channel();
        std::thread::spawn(move || sender.send(child.wait_with_output()));
        let Ok(output) = ended.recv_timeout(Duration::from_secs(60)) else {
            // SAFETY: kill sends a signal to the child this test started.
            unsafe { libc::kill(id as i32, libc::SIGKILL) };
            panic!("the hang went on past a minute");
        };
        let output = output.unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{stderr}");
        assert!(
            stderr.contains("threads (tid name state wchan):"),
            "{stderr}"
        );
        output
    }

    /// A wait that never ends aborts its process once past its bound,
    /// which writes the wait and the thread making it.
    #[test]
    fn a_hung_wait_aborts_saying_where_it_hung() {
        let test = "watch::tests::a_hung_wait_aborts_saying_where_it_hung";
        if hanging() {
            let (_sender, never) = mpsc::channel::<()>();
            let _watched = watched("an answer that never comes".into(), Duration::from_secs(1));
            let _ = never.recv();
            return;
        }
        let output = run_alone(test);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "`{test}` waited past 1s for an answer that never comes"
            )),
            "{stderr}"
        );
        assert!(
            stderr.contains(&format!("  {test}: an answer that never comes")),
            "{stderr}"
        );
    }

    /// A process that asked to be watched idle, with no wait pending past
    /// that bound, aborts too, naming the last wait each thread ended: a
    /// thread stuck once its waits are over is a hang as well.
    #[test]
    fn a_process_idle_past_its_bound_aborts() {
        let test = "watch::tests::a_process_idle_past_its_bound_aborts";
        if hanging() {
            idle(Duration::from_secs(1));
            drop(waiting("a wait that ends", Duration::ZERO));
            let (_sender, never) = mpsc::channel::<()>();
            let _ = std::thread::spawn(move || never.recv()).join();
            return;
        }
        let output = run_alone(test);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("no wait pending, and none begun or ended, for"),
            "{stderr}"
        );
        assert!(
            stderr.contains(&format!("  {test}: a wait that ends,")),
            "{stderr}"
        );
    }
}
