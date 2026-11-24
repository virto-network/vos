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
//!   a pass reads it open; a restore stopped and an alarm, which a pass
//!   raises once, stand for [`STANDS_MS`] after it, unless they are of an
//!   operation (the restore, the kit's signature on one) a later pass
//!   reads open no more, which they go with; one clock alarm stands, the
//!   latest skew's; a pass that reached nothing keeps every notice. The device
//!   group's alarms a pass found are acknowledged to it
//!   ([`Personal::acknowledge`]) once the run that raised them is kept:
//!   the group raises them no more, and the run's notices hold them.
//! - **After first unlock:** the job reads only what the facility's store
//!   holds in the app's credential-encrypted storage, readable from the
//!   first unlock after boot whether the screen is locked or not, and
//!   never a key behind a prompt; Android starts no job of the app before
//!   that unlock.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use vos_abi::{Decode, Encode};
use vos_light::group::Alarm;

use crate::kept::Kept;
use crate::{Code, Facility, JobRun, Notice, Pending, Refusal, Seen, Synced, refused};

/// The runs kept.
pub const RUNS: usize = 64;

/// How long a notice a pass raises once (a pending restore, an alarm)
/// stands: a week, so a locked phone's user sees it.
pub const STANDS_MS: u64 = 7 * 24 * 3_600_000;

/// The once-raised notices kept standing, the latest.
const STANDING: usize = 16;

/// The runs' row of the facility's database ([`crate::kept`]).
const RUNS_ROW: &[u8] = b"runs";

/// The row naming why the last personal pass failed (empty when it did
/// not), standing until a pass changes it.
const FAILED_ROW: &[u8] = b"runs/personal-failed";

/// The device's personal space, as a pass syncs it.
pub trait Personal: Send + Sync {
    /// One pass at the device's time `now` (milliseconds), called beside
    /// the facility's runtime, never on it: what it found, or why it
    /// reached nothing.
    fn pass(&self, now: u64) -> Result<Passed, String>;

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
#[derive(Clone, Debug)]
struct Raised {
    notice: Notice,
    since: u64,
}

/// The runs, the latest last, and the notices standing.
#[derive(Debug, Default)]
struct State {
    runs: Vec<JobRun>,
    raised: Vec<Raised>,
}

/// A run as its row keeps it.
#[derive(Encode, Decode)]
struct Run {
    started_ms: u64,
    finished_ms: u64,
    bytes_down: u64,
    bytes_up: u64,
    synced: u32,
    failed: u32,
    notices: u32,
    apart: bool,
}

/// A notice standing as its row keeps it: its kinds' bytes.
#[derive(Encode, Decode)]
struct Stood {
    pending: u8,
    index: u64,
    at: u64,
    matures: u64,
    fresh: bool,
    by: u32,
    by_kit: bool,
    contested: bool,
    alarm: u8,
    remedy: u8,
    since: u64,
}

/// The runs' row.
#[derive(Encode, Decode)]
struct Row {
    runs: Vec<Run>,
    raised: Vec<Stood>,
}

impl From<&State> for Row {
    fn from(state: &State) -> Self {
        Row {
            runs: state
                .runs
                .iter()
                .map(|run| Run {
                    started_ms: run.started_ms,
                    finished_ms: run.finished_ms,
                    bytes_down: run.bytes_down,
                    bytes_up: run.bytes_up,
                    synced: run.synced,
                    failed: run.failed,
                    notices: run.notices,
                    apart: run.apart,
                })
                .collect(),
            raised: state
                .raised
                .iter()
                .map(|raised| Stood {
                    pending: raised.notice.pending as u8,
                    index: raised.notice.index,
                    at: raised.notice.at,
                    matures: raised.notice.matures,
                    fresh: raised.notice.fresh,
                    by: raised.notice.by,
                    by_kit: raised.notice.by_kit,
                    contested: raised.notice.contested,
                    alarm: raised.notice.alarm as u8,
                    remedy: raised.notice.remedy as u8,
                    since: raised.since,
                })
                .collect(),
        }
    }
}

impl Row {
    /// The state it keeps; a notice of a kind this build does not know is
    /// a row in need of repair.
    fn state(self) -> Result<State, String> {
        let raised = self
            .raised
            .into_iter()
            .map(|stood| {
                let unknown = "the facility's database needs repair: a notice's kind is not known";
                let pending = Pending::from_byte(stood.pending).ok_or(unknown)?;
                let alarm =
                    crate::personal::contract::Alarm::from_byte(stood.alarm).ok_or(unknown)?;
                let remedy =
                    crate::personal::contract::Remedy::from_byte(stood.remedy).ok_or(unknown)?;
                Ok(Raised {
                    notice: Notice {
                        pending,
                        index: stood.index,
                        at: stood.at,
                        matures: stood.matures,
                        fresh: stood.fresh,
                        by: stood.by,
                        by_kit: stood.by_kit,
                        contested: stood.contested,
                        alarm,
                        remedy,
                        // Kept are those raised once, none of a contest.
                        ..Notice::default()
                    },
                    since: stood.since,
                })
            })
            .collect::<Result<_, String>>()?;
        let runs = self
            .runs
            .into_iter()
            .map(|run| JobRun {
                started_ms: run.started_ms,
                finished_ms: run.finished_ms,
                bytes_down: run.bytes_down,
                bytes_up: run.bytes_up,
                synced: run.synced,
                failed: run.failed,
                notices: run.notices,
                apart: run.apart,
            })
            .collect();
        Ok(State { runs, raised })
    }
}

/// Whether a pass raises `notice` once rather than while its condition
/// holds.
fn once(notice: &Notice) -> bool {
    matches!(
        notice.pending,
        Pending::Restoring | Pending::Alarm | Pending::Unfinished
    )
}

/// The job's runs, a row of the facility's database under its directory.
pub struct Runs {
    kept: Result<Kept, String>,
}

impl Runs {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            kept: Kept::open(&directory.into()),
        }
    }

    fn kept(&self) -> Result<&Kept, String> {
        self.kept.as_ref().map_err(Clone::clone)
    }

    /// The state kept, read strictly.
    fn read(&self) -> Result<State, String> {
        match self.kept()?.get::<Row>(RUNS_ROW)? {
            Some(row) => row.state(),
            None => Ok(State::default()),
        }
    }

    fn write(&self, state: &State) -> Result<(), String> {
        self.kept()?.put(RUNS_ROW, &Row::from(state))
    }

    fn failed(&self) -> Result<Option<String>, String> {
        self.kept()?.get(FAILED_ROW)
    }

    fn write_failed(&self, failures: &str) -> Result<(), String> {
        self.kept()?.put(FAILED_ROW, &failures.to_owned())
    }

    /// The runs kept, the latest last.
    pub fn all(&self) -> Result<Vec<JobRun>, String> {
        Ok(self.read()?.runs)
    }
}

fn job_error(error: String) -> Refusal {
    refused(
        Code::Store,
        format!("the background job's runs could not be read or kept: {error}"),
    )
}

/// The device's time, in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// A notice's key among the raised: what it is, and where.
fn key(notice: &Notice) -> (u8, u64, u8, u32, bool) {
    // One clock alarm stands, the latest skew's.
    let clock =
        notice.pending == Pending::Alarm && notice.alarm == crate::personal::contract::Alarm::Clock;
    (
        notice.pending as u8,
        if clock { 0 } else { notice.index },
        notice.alarm as u8,
        notice.by,
        notice.by_kit,
    )
}

/// The operation a notice raised once is of, by its log index: a restore
/// stopped, or the kit's signature on an operation.
fn operation_of(notice: &Notice) -> Option<u64> {
    match notice.pending {
        Pending::Restoring => Some(notice.index),
        Pending::Alarm if notice.alarm == crate::personal::contract::Alarm::Kit => {
            Some(notice.index)
        }
        _ => None,
    }
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
        *crate::lock(&self.personal) = Some(personal);
    }

    pub fn runs(&self) -> Result<Vec<JobRun>, Refusal> {
        self.runs.all().map_err(job_error)
    }

    /// Why the last personal pass failed, as its run's failures say; empty
    /// when it did not.
    pub fn failed(&self) -> Result<String, Refusal> {
        Ok(self.runs.failed().map_err(job_error)?.unwrap_or_default())
    }

    /// A flow's follows left for after it failed at the device's time
    /// `now`: a notice stands until a pass of the personal
    /// space runs to its end, which finishes what they left.
    pub fn unfinished(&self, now: u64) {
        let _one = crate::lock(&self.running);
        let Ok(mut state) = self.runs.read() else {
            return;
        };
        let notice = Notice {
            pending: Pending::Unfinished,
            at: now,
            fresh: true,
            ..Notice::default()
        };
        state
            .raised
            .retain(|raised| raised.notice.pending != Pending::Unfinished);
        state.raised.push(Raised { notice, since: now });
        let _ = self.runs.write(&state);
    }

    /// A flow's follows left for after it finished: a notice of earlier
    /// ones failing goes.
    pub fn finished(&self) {
        let _one = crate::lock(&self.running);
        let Ok(mut state) = self.runs.read() else {
            return;
        };
        let before = state.raised.len();
        state
            .raised
            .retain(|raised| raised.notice.pending != Pending::Unfinished);
        if state.raised.len() != before {
            let _ = self.runs.write(&state);
        }
    }

    /// The device holds its group, following it: a notice that it is out
    /// of it (removed, stuck) applies no more; and once it `rejoined`
    /// (paired again, restored, claimed), neither do the restores it
    /// stopped nor the kit's operations it raised before.
    pub fn following(&self, rejoined: bool) {
        let _one = crate::lock(&self.running);
        let Ok(mut state) = self.runs.read() else {
            return;
        };
        let before = state.raised.len();
        state.raised.retain(|raised| {
            let notice = &raised.notice;
            !matches!(notice.pending, Pending::Removed | Pending::Stuck)
                && !(rejoined && (notice.pending == Pending::Restoring || kit_alarm(notice)))
        });
        if state.raised.len() != before {
            let _ = self.runs.write(&state);
        }
    }

    /// The notices standing after the last pass.
    pub fn standing(&self) -> Result<Vec<Notice>, Refusal> {
        let state = self.runs.read().map_err(job_error)?;
        Ok(state
            .raised
            .into_iter()
            .map(|raised| raised.notice)
            .collect())
    }

    /// One run of `part` on `runtime`: the run written as started first
    /// and as finished last.
    pub fn run(
        &self,
        runtime: &tokio::runtime::Runtime,
        facility: &Facility,
        part: Part,
    ) -> Result<Synced, Refusal> {
        let _one = crate::lock(&self.running);
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
                    .unwrap_or_else(|refusal| Synced {
                        failed: 1,
                        failures: refusal.to_string(),
                        ..Synced::default()
                    })
            }
            Part::Personal => {
                let personal = crate::lock(&self.personal).clone();
                if let Some(personal) = personal {
                    synced.enrollments = 1;
                    match personal.pass(now) {
                        Ok(passed) => {
                            match passed.stopped {
                                None => synced.synced = 1,
                                // Stopped: what it found is the device
                                // group's own state (its operations, its
                                // course) and the alarms raised so far.
                                Some(why) => {
                                    synced.failed = 1;
                                    synced.failures = why;
                                }
                            }
                            synced.seen = passed.seen;
                            found = Some(passed.notices);
                            alarms = passed.alarms;
                            acknowledging = Some(personal);
                        }
                        Err(why) => {
                            synced.failed = 1;
                            synced.failures = why;
                        }
                    }
                }
            }
        }
        state.raised = standing(std::mem::take(&mut state.raised), found, now);
        // A personal pass run to its end finishes what a flow's follows
        // left.
        if part == Part::Personal && synced.synced == 1 {
            state
                .raised
                .retain(|raised| raised.notice.pending != Pending::Unfinished);
        }
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
        if part == Part::Personal {
            self.runs
                .write_failed(&synced.failures)
                .map_err(job_error)?;
        }
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
        return one_an_event(
            before
                .into_iter()
                .map(|raised| Raised {
                    notice: Notice {
                        fresh: false,
                        ..raised.notice
                    },
                    ..raised
                })
                .collect(),
        );
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
    // An operation the pass found open is raised as one; a notice raised
    // once of an operation found open no more goes with it.
    let open = |index: u64| {
        after.iter().any(|found| {
            found.notice.index == index
                && !matches!(found.notice.pending, Pending::Alarm | Pending::Restoring)
        })
    };
    let mut kept: Vec<Raised> = before
        .into_iter()
        .filter(|raised| {
            once(&raised.notice)
                && now.saturating_sub(raised.since) < STANDS_MS
                && operation_of(&raised.notice).is_none_or(open)
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
    one_an_event(after)
}

/// One notice an event: the kit's alarm of an operation whose own notice
/// stands (the operation open, signed by the kit; the restore this device
/// stopped) says nothing more.
fn one_an_event(mut raised: Vec<Raised>) -> Vec<Raised> {
    let told: Vec<u64> = raised
        .iter()
        .filter(|one| one.notice.pending as u8 <= Pending::Restoring as u8)
        .map(|one| one.notice.index)
        .collect();
    raised.retain(|one| !(kit_alarm(&one.notice) && told.contains(&one.notice.index)));
    raised
}

/// Whether `notice` is the kit's alarm: the kit signed an operation.
fn kit_alarm(notice: &Notice) -> bool {
    notice.pending == Pending::Alarm && notice.alarm == crate::personal::contract::Alarm::Kit
}

/// A notice of the light node's pass, as the chrome raises it.
pub(crate) fn notice(raised: vos_light::job::Notice) -> Notice {
    use vos_light::job::{Kind, Notice as Found};
    let plain = |pending| Notice {
        pending,
        ..Notice::default()
    };
    match raised {
        Found::Operation {
            index,
            by,
            kind,
            target,
            matures,
            contested,
            at,
            cannot_resolve,
            kit_only,
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
            by: match by {
                vos_wire::personal::Signer::Device(device) => device,
                vos_wire::personal::Signer::Kit(_) => 0,
            },
            by_kit: matches!(by, vos_wire::personal::Signer::Kit(_)),
            contested,
            cannot_resolve,
            kit_only,
            target: target.unwrap_or(0),
            targeted: target.is_some(),
            ..Notice::default()
        },
        Found::Restore { index } => Notice {
            index,
            ..plain(Pending::Restoring)
        },
        Found::Removed => plain(Pending::Removed),
        Found::Stuck => plain(Pending::Stuck),
        Found::Commit(vos_light::job::Commit::Removals) => plain(Pending::Commit),
        Found::Commit(vos_light::job::Commit::Reseal) => plain(Pending::Reseal),
        Found::Alarm(found) => {
            let (alarm, index, remedy) = alarm(&found);
            Notice {
                index,
                alarm,
                remedy,
                ..plain(Pending::Alarm)
            }
        }
    }
}

/// An alarm's kind, its place (a log index, an epoch, a position, a skew
/// in seconds) and its remedy: each kind its own, so one this build does
/// not name fails to build.
fn alarm(
    alarm: &Alarm,
) -> (
    crate::personal::contract::Alarm,
    u64,
    crate::personal::contract::Remedy,
) {
    use crate::personal::contract::{Alarm as Kind, Remedy};
    let none = Remedy::None;
    match *alarm {
        Alarm::Log { index } => (Kind::Log, index, none),
        Alarm::SplitLog { epoch, .. } => (Kind::SplitLog, epoch, none),
        Alarm::NamedAbsent { epoch, .. } => (Kind::NamedAbsent, epoch, none),
        Alarm::Refused { epoch, .. } => (Kind::Refused, epoch, none),
        Alarm::CannotFollow { epoch, remedy, .. } => (
            Kind::CannotFollow,
            epoch,
            match remedy {
                vos_light::group::Remedy::RePair => Remedy::RePair,
                vos_light::group::Remedy::Regroup => Remedy::Regroup,
            },
        ),
        Alarm::Verdict { epoch } => (Kind::Verdict, epoch, none),
        Alarm::Unsigned { index } => (Kind::Unsigned, index, none),
        Alarm::Clock { skew_ms } => (Kind::Clock, skew_ms / 1_000, none),
        Alarm::Kit { index } => (Kind::Kit, index, none),
        Alarm::Rollback { next } => (Kind::Rollback, next, none),
        Alarm::View { index } => (Kind::View, index, none),
        Alarm::Dropped { index } => (Kind::Dropped, index, none),
        Alarm::Partition { position, .. } => (Kind::Partition, position, none),
        Alarm::Withheld { position, .. } => (Kind::Withheld, position, none),
        Alarm::Stale { position, .. } => (Kind::Stale, position, none),
        Alarm::Author { position, .. } => (Kind::Author, position, none),
        Alarm::Deleted { position, .. } => (Kind::Deleted, position, none),
        Alarm::Unserved { next } => (Kind::Unserved, next, none),
        Alarm::Policy { index } => (Kind::Policy, index, none),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personal::contract::Alarm as Kind;

    fn raised(notice: Notice, since: u64) -> Raised {
        Raised { notice, since }
    }

    /// A restore stopped and the kit's alarm of it, raised once: they stand
    /// while a pass reads the restore open, and go with it once a pass
    /// reads it open no more.
    #[test]
    fn a_closed_operations_notices_go() {
        let restoring = Notice {
            pending: Pending::Restoring,
            index: 18,
            ..Notice::default()
        };
        let kit = Notice {
            pending: Pending::Alarm,
            alarm: Kind::Kit,
            index: 18,
            ..Notice::default()
        };
        let before = vec![raised(restoring.clone(), 1), raised(kit.clone(), 1)];
        let open = Notice {
            pending: Pending::Restore,
            index: 18,
            by_kit: true,
            ..Notice::default()
        };
        let stood = standing(before.clone(), Some(vec![open]), 2);
        assert_eq!(stood.len(), 2, "{stood:?}");
        assert!(
            !stood.iter().any(|raised| kit_alarm(&raised.notice)),
            "one notice an event: the kit's alarm goes with the restore's own"
        );
        let gone = standing(before.clone(), Some(Vec::new()), 2);
        assert!(gone.is_empty(), "{gone:?}");
        let unreached = standing(before, None, 2);
        assert_eq!(
            unreached.len(),
            1,
            "a pass that reached nothing keeps them, one an event"
        );
        // The kit's alarm of an operation with no notice of its own stands.
        let alone = standing(Vec::new(), Some(vec![kit.clone()]), 2);
        assert_eq!(alone.len(), 1);
    }

    /// Following its group, the device's notices of being out of it go;
    /// back in it, so do the restores it stopped and the kit's alarms.
    #[test]
    fn notices_that_apply_no_more_go() {
        let directory = tempfile::tempdir().unwrap();
        let job = Job::new(directory.path());
        let plain = |pending| Notice {
            pending,
            ..Notice::default()
        };
        let kit = Notice {
            alarm: Kind::Kit,
            index: 14,
            ..plain(Pending::Alarm)
        };
        let all = vec![
            raised(plain(Pending::Removed), 1),
            raised(kit.clone(), 1),
            raised(plain(Pending::Commit), 1),
        ];
        let mut state = job.runs.read().unwrap();
        state.raised = all;
        job.runs.write(&state).unwrap();
        job.following(false);
        let pending: Vec<Pending> = job.standing().unwrap().iter().map(|n| n.pending).collect();
        assert_eq!(pending, [Pending::Alarm, Pending::Commit]);
        job.following(true);
        let pending: Vec<Pending> = job.standing().unwrap().iter().map(|n| n.pending).collect();
        assert_eq!(pending, [Pending::Commit]);
    }

    /// A clock alarm of another skew stands in the place of the last one.
    #[test]
    fn one_clock_alarm_stands() {
        let clock = |skew| Notice {
            pending: Pending::Alarm,
            alarm: Kind::Clock,
            index: skew,
            ..Notice::default()
        };
        let stood = standing(vec![raised(clock(4026), 1)], Some(vec![clock(18194)]), 2);
        assert_eq!(stood.len(), 1, "{stood:?}");
        assert_eq!(stood[0].notice.index, 18194);
        assert!(!stood[0].notice.fresh);
    }

    /// An alarm is raised as its kind, its place and its remedy.
    #[test]
    fn an_alarm_is_raised_as_its_kind() {
        let raised = notice(vos_light::job::Notice::Alarm(Alarm::Policy { index: 4 }));
        assert_eq!(raised.pending, Pending::Alarm);
        assert_eq!(raised.alarm, crate::personal::contract::Alarm::Policy);
        assert_eq!(raised.index, 4);
        let stuck = notice(vos_light::job::Notice::Alarm(Alarm::CannotFollow {
            epoch: 3,
            committer: 1,
            remedy: vos_light::group::Remedy::Regroup,
        }));
        assert_eq!(
            (stuck.alarm, stuck.index, stuck.remedy),
            (
                crate::personal::contract::Alarm::CannotFollow,
                3,
                crate::personal::contract::Remedy::Regroup
            )
        );
    }
}
