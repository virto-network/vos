// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The background jobs as `:vos` runs them, over the world's gateway: the
//! spaces' run reads each tree from its feed, a run with nothing due reads
//! nothing, every byte through the node's client counted; each run is
//! kept, started then finished; and the personal space's job raises its
//! notices fresh once, carried while a pass cannot read the space, and
//! fresh again when they come back.

mod common;

use common::*;
use vos_facility::job::{Passed, Personal, RUNS};
use vos_facility::node::{Device, Node, Prompts};
use vos_facility::{Enroll, Notice, Pending, Seen};
use vos_light::group::Alarm;

/// A node enrolled in the world's space, the member in its tree.
fn enrolled(directory: &std::path::Path) -> (Node, Arc<World>) {
    let world = world();
    let phone = Arc::new(Phone::new(9));
    let node = node(&world, directory, Arc::clone(&phone) as Arc<dyn Device>);
    let session = node.open_session(gateway());
    let enrolled = node
        .enroll(
            session,
            Enroll::read(&enrollment()).unwrap(),
            phone as Arc<dyn Prompts>,
        )
        .unwrap();
    world.enroll(AGENT, &enrolled.member);
    node.close(session);
    (node, world)
}

/// The quiet day: a run reads the tree from its feed, on the space's feed
/// connection, then a run while the tree is not due reads nothing. Each
/// run is kept, finished, its bytes the run's.
#[test]
fn a_run_with_nothing_new_reads_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let (node, world) = enrolled(directory.path());
    let first = node.sync().unwrap();
    assert_eq!((first.enrollments, first.synced, first.failed), (1, 1, 0));
    eprintln!(
        "first run: {} bytes down, {} up, {} ms",
        first.bytes_down, first.bytes_up, first.millis
    );
    assert!(first.bytes_down > 0 && first.bytes_down < 64 << 10);
    let before = world.state.lock().unwrap().seen.len();
    let quiet = node.sync().unwrap();
    assert_eq!((quiet.enrollments, quiet.synced, quiet.failed), (1, 1, 0));
    assert_eq!(
        world.state.lock().unwrap().seen.len(),
        before,
        "no connection"
    );
    assert_eq!((quiet.bytes_down, quiet.bytes_up), (0, 0));
    assert!(quiet.notices.is_empty() && quiet.seen.is_empty());

    let runs = node.runs().unwrap();
    assert_eq!(runs.len(), 2);
    for (run, synced) in runs.iter().zip([&first, &quiet]) {
        assert!(run.finished_ms >= run.started_ms && run.started_ms > 0);
        assert!(!run.apart);
        assert_eq!(
            (run.bytes_down, run.bytes_up, run.synced, run.failed),
            (synced.bytes_down, synced.bytes_up, 1, 0)
        );
    }
    assert!(runs[0].started_ms <= runs[1].started_ms);
}

/// A personal space scripted pass by pass: unreachable once the script
/// ends. It records the alarms acknowledged.
#[derive(Default)]
struct Scripted {
    passes: Mutex<VecDeque<Result<Passed, String>>>,
    acknowledged: Mutex<Vec<Vec<Alarm>>>,
}

impl Scripted {
    fn new(passes: impl IntoIterator<Item = Result<Passed, String>>) -> Self {
        Self {
            passes: Mutex::new(passes.into_iter().collect()),
            ..Self::default()
        }
    }
}

impl Personal for Scripted {
    fn pass(&self, _now: u64) -> Result<Passed, String> {
        self.passes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err("the agent did not answer".into()))
    }

    fn acknowledge(&self, alarms: &[Alarm]) -> Result<(), String> {
        self.acknowledged.lock().unwrap().push(alarms.to_vec());
        Ok(())
    }
}

fn removal() -> Notice {
    Notice {
        pending: Pending::Remove,
        index: 12,
        at: 1_000,
        matures: 1_000 + 72 * 3_600_000,
        fresh: false,
        by: 1,
        ..Notice::default()
    }
}

/// The personal space's notices: fresh at the first run that raises
/// them, not at the next; carried, not fresh, through a run whose pass
/// fails; gone once a pass reads none; fresh again when they come back.
/// Each device's last call is the pass's.
#[test]
fn notices_are_fresh_once_and_stand_while_a_pass_fails() {
    let directory = tempfile::tempdir().unwrap();
    let (node, _world) = enrolled(directory.path());
    let raised = Passed {
        notices: vec![removal()],
        seen: vec![Seen { device: 1, at: 900 }],
        ..Passed::default()
    };
    let personal = Arc::new(Scripted::new([
        Ok(raised.clone()),
        Ok(raised.clone()),
        Err("the agent did not answer".into()),
        Ok(Passed::default()),
        Ok(raised.clone()),
    ]));
    node.attach(personal);
    let fresh = |synced: &vos_facility::Synced| {
        synced
            .notices
            .iter()
            .map(|notice| notice.fresh)
            .collect::<Vec<_>>()
    };

    let first = node.sync_personal().unwrap();
    assert_eq!((first.enrollments, first.synced, first.failed), (1, 1, 0));
    assert_eq!(fresh(&first), [true]);
    assert_eq!(first.seen, raised.seen);
    // The spaces' job raises them too, never fresh: it read nothing of them.
    let spaces = node.sync().unwrap();
    assert_eq!(fresh(&spaces), [false]);
    let second = node.sync_personal().unwrap();
    assert_eq!(fresh(&second), [false]);
    let failed = node.sync_personal().unwrap();
    assert_eq!((failed.synced, failed.failed), (0, 1));
    assert_eq!(failed.notices, vec![removal()], "carried, not fresh");
    let cleared = node.sync_personal().unwrap();
    assert!(cleared.notices.is_empty());
    let back = node.sync_personal().unwrap();
    assert_eq!(fresh(&back), [true]);

    let runs: Vec<_> = node
        .runs()
        .unwrap()
        .into_iter()
        .filter(|run| run.apart)
        .collect();
    assert_eq!(
        runs.iter().map(|run| run.notices).collect::<Vec<_>>(),
        [1, 1, 1, 0, 1]
    );
    assert_eq!(runs[2].failed, 1);
}

/// An alarm, which a pass raises once, stands after passes that find it
/// no more, not fresh, and through a pass that stopped, which raises what
/// it found. The device group's alarms are acknowledged to it once the
/// run that raised them is kept, and a pass that found none acknowledges
/// none.
#[test]
fn an_alarm_stands_after_the_pass_that_raised_it() {
    let directory = tempfile::tempdir().unwrap();
    let (node, _world) = enrolled(directory.path());
    let alarm = Notice {
        pending: Pending::Alarm,
        index: 4,
        alarm: vos_facility::personal::contract::Alarm::Rollback,
        ..Notice::default()
    };
    let rollback = Alarm::Rollback { next: 4 };
    let found = |notices: Vec<Notice>, stopped: Option<&str>| {
        let alarms = match notices
            .iter()
            .any(|notice| notice.pending == Pending::Alarm)
        {
            true => vec![rollback],
            false => Vec::new(),
        };
        Ok(Passed {
            notices,
            alarms,
            seen: Vec::new(),
            stopped: stopped.map(Into::into),
        })
    };
    let personal = Arc::new(Scripted::new([
        found(vec![alarm.clone()], None),
        found(vec![removal()], None),
        found(vec![removal()], Some("the agent refused")),
        found(Vec::new(), None),
    ]));
    node.attach(personal.clone());
    let shown = |synced: vos_facility::Synced| {
        synced
            .notices
            .into_iter()
            .map(|notice| (notice.pending, notice.fresh))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shown(node.sync_personal().unwrap()),
        [(Pending::Alarm, true)]
    );
    assert_eq!(*personal.acknowledged.lock().unwrap(), [vec![rollback]]);
    let kept = node.runs().unwrap();
    assert_eq!(
        kept.last().unwrap().notices,
        1,
        "the run that raised it, kept"
    );
    assert_eq!(
        shown(node.sync_personal().unwrap()),
        [(Pending::Remove, true), (Pending::Alarm, false)]
    );
    let stopped = node.sync_personal().unwrap();
    assert_eq!(stopped.failed, 1);
    assert_eq!(stopped.failures, "the agent refused", "why it stopped");
    assert_eq!(
        shown(stopped),
        [(Pending::Remove, false), (Pending::Alarm, false)],
        "a stopped pass raises what it found"
    );
    assert_eq!(
        shown(node.sync_personal().unwrap()),
        [(Pending::Alarm, false)]
    );
    assert_eq!(personal.acknowledged.lock().unwrap().len(), 1);
}

/// The runs kept are the latest [`RUNS`].
#[test]
fn the_latest_runs_are_kept() {
    let directory = tempfile::tempdir().unwrap();
    let (node, _world) = enrolled(directory.path());
    let personal = Arc::new(Scripted::default());
    node.attach(personal);
    for _ in 0..RUNS + 3 {
        let synced = node.sync_personal().unwrap();
        assert_eq!(synced.failed, 1, "the personal space unreachable");
    }
    let runs = node.runs().unwrap();
    assert_eq!(runs.len(), RUNS);
    assert!(runs.iter().all(|run| run.finished_ms > 0));
}
