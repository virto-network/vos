//! Faults a test injects into a running node, through a control file a
//! thread of its own reads every 50 ms: commits delayed, held or failing,
//! the node's clock moved, frames of one class lost, and QUIC's idle
//! timeout. Each line of the file is one fault:
//!
//! - `delay_commits <ms>`: each writer flush waits that long first;
//! - `hold_commits`: no flush until the line goes;
//! - `fail_commits before`: flushes fail with nothing written;
//! - `fail_commits after`: flushes are written but not synced, and fail,
//!   as a failed fsync does;
//! - `clock <ms>`: the node's clock runs that far ahead (or behind, below
//!   zero);
//! - `drop <class> <per million> [to <node>]`: frames of `liveness`,
//!   `consensus`, `requests` or `bulk` lost, to every peer or one;
//! - `quic_idle <ms>`: QUIC's idle timeout, read once at start;
//! - `election_ms <low> <high>`, `heartbeat_ms <ms>` and
//!   `compact <every> <tail>`: the groups' timing and compaction, read
//!   once at start;
//! - `generation <n>`: once the faults are in force, the node writes `n`
//!   to the file beside it, with the extension `taken`, so a test knows.
//!
//! Built only with the `faults` feature: a production build carries none
//! of it.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_net::{Class, Network, Refused};
use vos_wire::peer::NodeNumber;

use crate::{Config, Hooks, lock};

/// How often the control file is read.
const READ_EVERY: Duration = Duration::from_millis(50);

/// The faults in force, as the control file last said.
pub struct Faults {
    delay_commits: AtomicU64,
    hold_commits: AtomicBool,
    fail_before: AtomicBool,
    fail_after: AtomicBool,
    clock: AtomicI64,
    drops: Mutex<Vec<Loss>>,
    random: AtomicU64,
}

/// Frames of one class lost, out of a million, to one peer or all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Loss {
    class: Class,
    per_million: u32,
    to: Option<NodeNumber>,
}

/// What one reading of the control file says.
#[derive(Debug, Default, PartialEq, Eq)]
struct Read {
    delay_commits: u64,
    hold_commits: bool,
    fail_before: bool,
    fail_after: bool,
    clock: i64,
    drops: Vec<Loss>,
    quic_idle: Option<u64>,
    election_ms: Option<(u64, u64)>,
    heartbeat_ms: Option<u64>,
    compact: Option<(u64, u64)>,
    generation: Option<u64>,
    /// Settings lines it could not read: a node does not start on them.
    unreadable: Vec<String>,
}

fn class(name: &str) -> Option<Class> {
    Some(match name {
        "liveness" => Class::Liveness,
        "consensus" => Class::Consensus,
        "requests" => Class::Requests,
        "bulk" => Class::Bulk,
        _ => return None,
    })
}

/// The faults `text` names; a fault's line it cannot read is left out, a
/// setting's is kept as unreadable.
fn read(text: &str) -> Read {
    let mut read = Read::default();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words[..] {
            ["delay_commits", ms] => read.delay_commits = ms.parse().unwrap_or(0),
            ["hold_commits"] => read.hold_commits = true,
            ["fail_commits", "before"] => read.fail_before = true,
            ["fail_commits", "after"] => read.fail_after = true,
            ["clock", ms] => read.clock = ms.parse().unwrap_or(0),
            ["generation", n] => read.generation = n.parse().ok(),
            ["quic_idle" | "election_ms" | "heartbeat_ms" | "compact", ..] => {
                let read_as = |text: &str| text.parse::<u64>().ok();
                let taken = match words[..] {
                    ["quic_idle", ms] => read_as(ms).map(|ms| read.quic_idle = Some(ms)),
                    ["election_ms", low, high] => read_as(low)
                        .zip(read_as(high))
                        .filter(|(low, high)| low < high)
                        .map(|election| read.election_ms = Some(election)),
                    ["heartbeat_ms", ms] => read_as(ms)
                        .filter(|ms| *ms > 0)
                        .map(|ms| read.heartbeat_ms = Some(ms)),
                    ["compact", every, tail] => read_as(every)
                        .zip(read_as(tail))
                        .filter(|(every, _)| *every > 0)
                        .map(|compact| read.compact = Some(compact)),
                    _ => None,
                };
                if taken.is_none() {
                    read.unreadable.push(line.to_string());
                }
            }
            ["drop", name, per_million, ref rest @ ..] => {
                let to = match rest {
                    ["to", node] => node.parse().ok(),
                    _ => None,
                };
                if let (Some(class), Ok(per_million)) = (class(name), per_million.parse()) {
                    read.drops.push(Loss {
                        class,
                        per_million,
                        to,
                    });
                }
            }
            _ => {}
        }
    }
    read
}

impl Faults {
    /// Take the faults the control file at `path` names into `config`:
    /// its hooks and clock, and QUIC's idle timeout; then read the file
    /// again every 50 ms for as long as the process runs.
    pub fn install(config: &mut Config, path: &Path) -> std::io::Result<Arc<Faults>> {
        let faults = Arc::new(Faults {
            delay_commits: AtomicU64::new(0),
            hold_commits: AtomicBool::new(false),
            fail_before: AtomicBool::new(false),
            fail_after: AtomicBool::new(false),
            clock: AtomicI64::new(0),
            drops: Mutex::new(Vec::new()),
            random: AtomicU64::new(0x9e37_79b9_7f4a_7c15),
        });
        let invalid = |why: String| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {why}", path.display()),
            )
        };
        let first = read(&std::fs::read_to_string(path).unwrap_or_default());
        if !first.unreadable.is_empty() {
            return Err(invalid(format!(
                "unreadable settings {:?}",
                first.unreadable
            )));
        }
        if let Some(idle) = first.quic_idle {
            config.quic_idle = Duration::from_millis(idle);
        }
        if let Some(election) = first.election_ms {
            config.election_timeout_ms = election;
        }
        if let Some(heartbeat) = first.heartbeat_ms {
            config.heartbeat_ms = heartbeat;
        }
        if let Some((every, tail)) = first.compact {
            config.compact_every = every;
            config.compact_tail = tail;
        }
        if config.heartbeat_ms >= config.election_timeout_ms.0 {
            return Err(invalid(format!(
                "a heartbeat of {} ms within elections of {:?} ms",
                config.heartbeat_ms, config.election_timeout_ms
            )));
        }
        let mut taken = first.generation;
        faults.take(first);
        acknowledge(path, taken);
        let base = Arc::clone(&config.clock);
        let moved = Arc::clone(&faults);
        config.clock =
            Arc::new(move || base().saturating_add_signed(moved.clock.load(Ordering::Acquire)));
        config.hooks = Arc::new(FaultHooks(Arc::clone(&faults)));
        config.faults = Some(Arc::clone(&faults));
        let watched = Arc::clone(&faults);
        let path = path.to_path_buf();
        std::thread::Builder::new()
            .name("vos-faults".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(READ_EVERY);
                    let read = read(&std::fs::read_to_string(&path).unwrap_or_default());
                    let generation = read.generation;
                    watched.take(read);
                    if generation != taken {
                        acknowledge(&path, generation);
                        taken = generation;
                    }
                }
            })?;
        Ok(faults)
    }

    /// Put `read`'s faults in force: each store releases, so whatever
    /// follows, the acknowledgement among it, comes after them.
    fn take(&self, read: Read) {
        self.delay_commits
            .store(read.delay_commits, Ordering::Release);
        self.hold_commits
            .store(read.hold_commits, Ordering::Release);
        self.fail_before.store(read.fail_before, Ordering::Release);
        self.fail_after.store(read.fail_after, Ordering::Release);
        self.clock.store(read.clock, Ordering::Release);
        *lock(&self.drops) = read.drops;
    }

    /// Whether a frame of `class` to `to` is lost.
    pub(crate) fn lost(&self, to: NodeNumber, class: Class) -> bool {
        let losses = lock(&self.drops);
        let Some(loss) = losses
            .iter()
            .find(|loss| loss.class == class && loss.to.is_none_or(|node| node == to))
        else {
            return false;
        };
        // A xorshift step: frames lost at about the rate asked.
        let step = |mut x: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let last = self
            .random
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| Some(step(x)))
            .expect("a step always");
        step(last) % 1_000_000 < u64::from(loss.per_million)
    }
}

/// Say that the faults of `generation` are in force, in the file beside
/// the control file at `path`.
fn acknowledge(path: &Path, generation: Option<u64>) {
    let Some(generation) = generation else {
        return;
    };
    let staged = path.with_extension("taking");
    if std::fs::write(&staged, generation.to_string()).is_ok() {
        let _ = std::fs::rename(&staged, path.with_extension("taken"));
    }
}

/// A network losing the frames of the classes the faults name.
pub(crate) struct Lossy {
    pub(crate) network: Arc<dyn Network>,
    pub(crate) faults: Arc<Faults>,
}

impl Network for Lossy {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused> {
        if self.faults.lost(to, class) {
            return Ok(());
        }
        self.network.send(to, class, stream, frame)
    }

    fn ready(
        &self,
        to: NodeNumber,
        class: Class,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.network.ready(to, class)
    }
}

struct FaultHooks(Arc<Faults>);

impl Hooks for FaultHooks {
    fn before_commit(&self) {
        while self.0.hold_commits.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let delay = self.0.delay_commits.load(Ordering::Acquire);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
    }

    fn fail_commit(&self) -> bool {
        self.0.fail_before.load(Ordering::Acquire)
    }

    fn fail_sync(&self) -> bool {
        self.0.fail_after.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_file_reads_as_its_faults() {
        let read = read(
            "delay_commits 50\nhold_commits\nfail_commits after\nclock -15000\n\
             drop consensus 500000 to 2\ndrop liveness 1000000\nquic_idle 3000\ngeneration 7\n\
             election_ms 300 600\nheartbeat_ms 100\ncompact 32 8\nnonsense\n",
        );
        assert_eq!(
            read,
            Read {
                delay_commits: 50,
                hold_commits: true,
                fail_before: false,
                fail_after: true,
                clock: -15_000,
                drops: vec![
                    Loss {
                        class: Class::Consensus,
                        per_million: 500_000,
                        to: Some(2),
                    },
                    Loss {
                        class: Class::Liveness,
                        per_million: 1_000_000,
                        to: None,
                    },
                ],
                quic_idle: Some(3_000),
                election_ms: Some((300, 600)),
                heartbeat_ms: Some(100),
                compact: Some((32, 8)),
                generation: Some(7),
                unreadable: Vec::new(),
            }
        );
    }

    #[test]
    fn a_setting_it_cannot_read_is_kept_as_unreadable() {
        let read = read(
            "election_ms 600 300\nheartbeat_ms soon\nheartbeat_ms 0\ncompact 32\ncompact 0 8\n\
             hold_commits\n",
        );
        assert_eq!(
            read.unreadable,
            [
                "election_ms 600 300",
                "heartbeat_ms soon",
                "heartbeat_ms 0",
                "compact 32",
                "compact 0 8"
            ]
        );
        assert!(read.hold_commits);
    }
}
