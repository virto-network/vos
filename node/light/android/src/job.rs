// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The background job (VOS's `light-node.md` §2.2, §3.6 "Background
//! sync"): one pass of the facility's sync each time the operating system
//! runs the job in the `:vos` process, with no client at all.
//!
//! - **Two jobs, two parts** ([`Part`]): the spaces' (each enrollment's
//!   credential tree read from its feed if due) and the personal space's
//!   ([`Personal`], once the device holds one: the light node's control
//!   log followed and answered, `alive` posted while a restore is pending,
//!   each scope's queued operations pushed and its envelopes read by its
//!   cursor), each on its own schedule, so the personal agent's circuits
//!   and timing do not ride with every space's reads. The personal pass is
//!   its own isolation group (`Purpose::Background`).
//! - **Over Tor:** every connection is the facility's client's, counted
//!   ([`crate::net::Count`]).
//! - **Its runs are kept** ([`Runs`]), the latest [`RUNS`]: a run is
//!   written as started before anything is sent and as finished after, each
//!   write whole or not at all, so a run its process's death cut short
//!   shows as never finished and the store is the one the next run starts
//!   from. The device's last sync is the latest finished run's.
//! - **What it raises** ([`Notice`]): each a local notification the job
//!   posts, `fresh` when no earlier run raised it, so a notice alerts once
//!   while it stands and again if it comes back. An operation stands while
//!   a pass reads it open; a pending restore and an alarm, which a pass
//!   raises once, stand for [`STANDS_MS`] after it, whatever later passes
//!   read; a pass that reached nothing keeps every notice. The device
//!   group's alarms a pass found are acknowledged to it
//!   ([`Personal::acknowledge`]) once the run that raised them is kept:
//!   the group raises them no more, and the run's notices hold them.
//! - **After first unlock:** the job reads only what the facility's store
//!   holds in the app's credential-encrypted storage, readable from the
//!   first unlock after boot whether the screen is locked or not, and
//!   never a key behind a prompt; Android starts no job of the app before
//!   that unlock.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use vos_light::group::Alarm;

use crate::enrollment::{create_private, write_private};
use crate::{Code, Facility, JobRun, Notice, Pending, Refusal, Seen, Synced, refused};

/// The runs kept.
pub const RUNS: usize = 64;

/// How long a notice a pass raises once (a pending restore, an alarm)
/// stands: a week, so a locked phone's user sees it.
pub const STANDS_MS: u64 = 7 * 24 * 3_600_000;

/// The once-raised notices kept standing, the latest.
const STANDING: usize = 16;

/// The runs' file, beside the enrollments (which are `.toml`).
const FILE: &str = "job.state";

/// The device's personal space, as a pass syncs it.
pub trait Personal: Send + Sync {
    /// One pass at the device's time `now` (milliseconds), its requests
    /// driven on `runtime` (the facility's, which the pass is called
    /// beside, never on): what it found, or why it reached nothing.
    fn pass(&self, now: u64, runtime: &tokio::runtime::Handle) -> Result<Passed, String>;

    /// The device group's `alarms`, raised by a pass, are kept as the
    /// run's notices: the group keeps them no more.
    fn acknowledge(&self, alarms: &[Alarm]) -> Result<(), String>;
}

/// What a run syncs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// Every enrollment's credential tree.
    Spaces,
    /// The personal space, on its own schedule and its own circuits.
    Personal,
}

/// What the personal space's pass found: its notices (none `fresh` yet),
/// the device group's alarms among them, each device's last call, and the
/// error it stopped on, if it did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Passed {
    pub notices: Vec<Notice>,
    pub alarms: Vec<Alarm>,
    pub seen: Vec<Seen>,
    pub stopped: Option<String>,
}

/// A notice raised, and the device's time it was first raised at.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Raised {
    notice: Notice,
    since: u64,
}

/// What the runs' file holds: the runs, the latest last, and the notices
/// standing.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    runs: Vec<JobRun>,
    raised: Vec<Raised>,
}

/// Whether a pass raises `notice` once rather than while its condition
/// holds.
fn once(notice: &Notice) -> bool {
    matches!(notice.pending, Pending::Restoring | Pending::Alarm)
}

/// The job's runs, kept under the facility's directory.
pub struct Runs {
    directory: PathBuf,
}

impl Runs {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.join(FILE)
    }

    /// The state kept; a file that does not parse (another layout's) is
    /// started anew rather than stopping every run after it.
    fn read(&self) -> Result<State, String> {
        let path = self.path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(toml::from_str(&text).unwrap_or_default()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(error) => Err(failure(&path, error)),
        }
    }

    fn write(&self, state: &State) -> Result<(), String> {
        let text = toml::to_string(state).map_err(|error| error.to_string())?;
        create_private(&self.directory)?;
        write_private(&self.path(), text.as_bytes())
    }

    /// The runs kept, the latest last.
    pub fn all(&self) -> Result<Vec<JobRun>, String> {
        Ok(self.read()?.runs)
    }
}

fn failure(path: &Path, error: impl std::fmt::Display) -> String {
    format!("{}: {error}", path.display())
}

fn job_error(_: String) -> Refusal {
    refused(
        Code::Store,
        "the background job's runs could not be read or kept",
    )
}

/// The device's time, in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// A notice's key among the raised: what it is, where, and its detail.
fn key(notice: &Notice) -> String {
    format!(
        "{}:{}:{}",
        notice.pending as u8, notice.index, notice.detail
    )
}

/// The background job: its runs, the personal space once the device holds
/// one, and one pass at a time.
pub struct Job {
    runs: Runs,
    personal: Mutex<Option<Arc<dyn Personal>>>,
    running: Mutex<()>,
}

impl Job {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            runs: Runs::new(directory),
            personal: Mutex::new(None),
            running: Mutex::new(()),
        }
    }

    /// The personal space each pass syncs from now on.
    pub fn attach(&self, personal: Arc<dyn Personal>) {
        *self.personal.lock().unwrap_or_else(|e| e.into_inner()) = Some(personal);
    }

    pub fn runs(&self) -> Result<Vec<JobRun>, Refusal> {
        self.runs.all().map_err(job_error)
    }

    /// One run of `part` on `runtime`: the run written as started first
    /// and as finished last.
    pub fn run(
        &self,
        runtime: &tokio::runtime::Runtime,
        facility: &Facility,
        part: Part,
    ) -> Result<Synced, Refusal> {
        let _one = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let clock = Instant::now();
        let mut state = self.runs.read().map_err(job_error)?;
        let started_ms = now_ms();
        state.runs.push(JobRun {
            started_ms,
            apart: part == Part::Personal,
            ..JobRun::default()
        });
        if state.runs.len() > RUNS {
            state.runs.drain(..state.runs.len() - RUNS);
        }
        self.runs.write(&state).map_err(job_error)?;

        let count = facility.net().count();
        let (down, up) = count.bytes();
        let mut synced = Synced::default();
        let mut found = None;
        let mut alarms = Vec::new();
        let mut acknowledging = None;
        let now = now_ms();
        match part {
            // The enrollments unread are one failure: the run still
            // finished.
            Part::Spaces => {
                synced = runtime
                    .block_on(facility.sync())
                    .unwrap_or_else(|_| Synced {
                        failed: 1,
                        ..Synced::default()
                    })
            }
            Part::Personal => {
                let personal = self
                    .personal
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(personal) = personal {
                    synced.enrollments = 1;
                    match personal.pass(now, runtime.handle()) {
                        Ok(passed) => {
                            if passed.stopped.is_none() {
                                synced.synced = 1;
                            } else {
                                // Stopped: what it found is the device
                                // group's own state (its operations, its
                                // course) and the alarms raised so far.
                                synced.failed = 1;
                            }
                            synced.seen = passed.seen;
                            found = Some(passed.notices);
                            alarms = passed.alarms;
                            acknowledging = Some(personal);
                        }
                        Err(_) => synced.failed = 1,
                    }
                }
            }
        }
        state.raised = standing(std::mem::take(&mut state.raised), found, now);
        synced.notices = state
            .raised
            .iter()
            .map(|raised| raised.notice.clone())
            .collect();
        let (after_down, after_up) = count.bytes();
        (synced.bytes_down, synced.bytes_up) = (after_down - down, after_up - up);
        synced.millis = clock.elapsed().as_millis() as u64;
        if let Some(run) = state
            .runs
            .iter_mut()
            .rev()
            .find(|run| run.started_ms == started_ms)
        {
            *run = JobRun {
                started_ms,
                finished_ms: now_ms().max(started_ms),
                bytes_down: synced.bytes_down,
                bytes_up: synced.bytes_up,
                synced: synced.synced,
                failed: synced.failed,
                notices: synced.notices.len() as u32,
                apart: part == Part::Personal,
            };
        }
        self.runs.write(&state).map_err(job_error)?;
        // Kept: the group may let them go. One not acknowledged is raised
        // again, and stands as one already raised.
        if let Some(personal) = acknowledging
            && !alarms.is_empty()
        {
            let _ = personal.acknowledge(&alarms);
        }
        Ok(synced)
    }
}

/// The notices standing after a pass that found `found` (none when it
/// reached nothing), at the device's time `now`: what it found, each
/// `fresh` unless it stood already; those it raises once and found no
/// more, while younger than [`STANDS_MS`]; every one, when it found
/// nothing.
fn standing(before: Vec<Raised>, found: Option<Vec<Notice>>, now: u64) -> Vec<Raised> {
    let Some(found) = found else {
        return before
            .into_iter()
            .map(|raised| Raised {
                notice: Notice {
                    fresh: false,
                    ..raised.notice
                },
                ..raised
            })
            .collect();
    };
    let mut after: Vec<Raised> = found
        .into_iter()
        .map(|notice| {
            let stood = before
                .iter()
                .find(|raised| key(&raised.notice) == key(&notice));
            Raised {
                since: stood.map_or(now, |raised| raised.since),
                notice: Notice {
                    fresh: stood.is_none(),
                    ..notice
                },
            }
        })
        .collect();
    let mut kept: Vec<Raised> = before
        .into_iter()
        .filter(|raised| {
            once(&raised.notice)
                && now.saturating_sub(raised.since) < STANDS_MS
                && !after
                    .iter()
                    .any(|now| key(&now.notice) == key(&raised.notice))
        })
        .map(|raised| Raised {
            notice: Notice {
                fresh: false,
                ..raised.notice
            },
            ..raised
        })
        .collect();
    if kept.len() > STANDING {
        kept.drain(..kept.len() - STANDING);
    }
    after.append(&mut kept);
    after
}

/// A notice of the light node's pass, as the chrome raises it.
pub(crate) fn notice(raised: vos_light::job::Notice) -> Notice {
    use vos_light::job::{Kind, Notice as Found};
    let plain = |pending| Notice {
        pending,
        index: 0,
        at: 0,
        matures: 0,
        fresh: false,
        detail: String::new(),
    };
    match raised {
        Found::Operation {
            index,
            by,
            kind,
            matures,
            contested,
            at,
        } => Notice {
            pending: match kind {
                Kind::Add => Pending::Add,
                Kind::Remove => Pending::Remove,
                Kind::Replace => Pending::Replace,
                Kind::Rotate => Pending::Rotate,
                Kind::Regroup => Pending::Regroup,
                Kind::Restore => Pending::Restore,
            },
            index,
            at: at.unwrap_or(0),
            matures,
            fresh: false,
            detail: match (by, contested) {
                (vos_wire::personal::Signer::Kit(_), _) => "by the kit".into(),
                (vos_wire::personal::Signer::Device(device), false) => {
                    format!("by device {device}")
                }
                (vos_wire::personal::Signer::Device(device), true) => {
                    format!("by device {device}, contested")
                }
            },
        },
        Found::Restore => plain(Pending::Restoring),
        Found::Removed => plain(Pending::Removed),
        Found::Stuck => plain(Pending::Stuck),
        Found::Alarm(alarm) => Notice {
            detail: described(&alarm),
            ..plain(Pending::Alarm)
        },
    }
}

/// What the chrome says of `alarm`: each kind in its own words, so a kind
/// this build does not name fails to build rather than show as code.
pub(crate) fn described(alarm: &Alarm) -> String {
    match alarm {
        Alarm::Log { index } => format!("the log does not chain at entry {index}"),
        Alarm::SplitLog { epoch, device } => {
            format!("device {device}'s vote on epoch {epoch} is of another log")
        }
        Alarm::NamedAbsent { epoch, .. } => {
            format!("epoch {epoch} names this device absent though it called")
        }
        Alarm::Refused { epoch, committer } => {
            format!("this device refused device {committer}'s epoch {epoch}")
        }
        Alarm::CannotFollow {
            epoch, committer, ..
        } => format!("this device cannot follow device {committer}'s epoch {epoch}"),
        Alarm::Verdict { epoch } => {
            format!("the agent's verdict on epoch {epoch} is not this device's")
        }
        Alarm::Unsigned { index } => format!("log entry {index} matures with no evidence"),
        Alarm::Clock { skew_ms } => format!(
            "this device's clock is {} s off the agent's",
            skew_ms / 1_000
        ),
        Alarm::Kit { index } => format!("the kit signed operation {index}"),
        Alarm::Rollback { next } => format!("the agent's log went back to {next}"),
        Alarm::View { index } => format!("a device saw log entry {index} otherwise"),
        Alarm::Dropped { index } => format!("this device's call at {index} is not in the log"),
        Alarm::Partition { scope, position } => {
            format!("the agent serves less of {scope:?} than {position}, which a device read")
        }
        Alarm::Withheld { scope, position } => {
            format!("the agent withheld {scope:?} at {position}")
        }
        Alarm::Stale { scope, position } => {
            format!("{scope:?} at {position} is sealed under a past epoch")
        }
        Alarm::Author { scope, position } => {
            format!("{scope:?} at {position} is by no device of the set")
        }
        Alarm::Deleted { scope, position } => {
            format!("this device's {scope:?} at {position} is gone: pushed again")
        }
        Alarm::Unserved { next } => {
            format!("the agent named its log's head at {next} and served less of it")
        }
        Alarm::Policy { index } => {
            format!("log entry {index} lowers the device set's delays: refused")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alarms a pass raises name themselves: the head served short and
    /// a lowered policy among them.
    #[test]
    fn an_alarm_names_itself() {
        assert!(described(&Alarm::Unserved { next: 9 }).contains("head at 9"));
        assert!(described(&Alarm::Policy { index: 4 }).contains("entry 4 lowers"));
        let raised = notice(vos_light::job::Notice::Alarm(Alarm::Policy { index: 4 }));
        assert_eq!(raised.pending, Pending::Alarm);
        assert_eq!(raised.detail, described(&Alarm::Policy { index: 4 }));
    }
}
