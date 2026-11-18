//! B18: `Personal`'s layout is append-only across versions, since an
//! install replaces the program and touches no table. The next version,
//! installed over a populated agent, reads every envelope and operation
//! back and goes on.

use vos_abi::abi::cap::Target;
use vos_testkit::node::ran;
use vos_testkit::programs::derived;
use vos_wire::batch::{Admin, Input};
use vos_wire::personal::{
    Acknowledged, Candidacy, DeviceView, Entry, Envelope, InboxItem, Operation, Overview,
    Recipient, Recorded, RecoveryView, Verdict, Voted,
};

use vos_abi::{SpaceId, WindowClock};

use super::*;

/// Everything the agent answers its devices: the overview, the device
/// set, the log, every scope's envelopes, the inbox and the frontiers.
#[derive(Debug, PartialEq)]
struct Everything {
    overview: Overview,
    devices: Vec<DeviceView>,
    log: Vec<(u64, Entry)>,
    scopes: Vec<Vec<Envelope>>,
    inbox: Vec<InboxItem>,
    acks: Vec<Vec<Acknowledged>>,
    frontiers: Vec<Vec<(Scope, u64)>>,
    operations: Vec<(u64, Operation)>,
    recovery: RecoveryView,
}

fn everything(home: &Home) -> Everything {
    let mut log: Vec<(u64, Entry)> = Vec::new();
    loop {
        let from = log.last().map_or(0, |(index, _)| index + 1);
        let answer: Vec<(u64, Entry)> = home.query(sync(0), "log", from).unwrap();
        if answer.is_empty() {
            break;
        }
        log.extend(answer);
    }
    let scopes = (1..=3)
        .map(|n| {
            let mut read: Vec<Envelope> = Vec::new();
            loop {
                let at = read.last().map_or(0, |envelope| envelope.position);
                let answer: Vec<Envelope> = home.query(sync(0), "since", (scope(n), at)).unwrap();
                if answer.is_empty() {
                    break read;
                }
                read.extend(answer);
            }
        })
        .collect();
    Everything {
        overview: home.overview(),
        devices: home.query(sync(0), "devices", ()).unwrap(),
        log,
        scopes,
        inbox: home
            .query(sync(0), "inbox", None::<(u64, [u8; 16])>)
            .unwrap(),
        acks: (1..=3)
            .map(|n| {
                home.query(sync(0), "acknowledgements", (scope(n), 0u64))
                    .unwrap()
            })
            .collect(),
        frontiers: (0..3u32)
            .map(|device| home.query(sync(0), "frontier", device).unwrap())
            .collect(),
        operations: home.query(sync(0), "operations", None::<u64>).unwrap(),
        recovery: home.query(sync(0), "recovery", ()).unwrap(),
    }
}

/// An agent with devices added and removed, commits confirmed and void,
/// evidence, envelopes across scopes, the inbox, and device-set operations
/// open, contested and cancelled; the next version
/// installed over it reads all of it back as the version before did, and
/// takes the next push and commit.
#[test]
fn the_next_version_installed_over_a_populated_agent_reads_everything_back() {
    let mut home = Home::new();
    home.pair(0, 1);
    home.pair(0, 2);
    for n in 0..30u8 {
        let len = if n.is_multiple_of(10) {
            50 << 10
        } else {
            200 + n as usize * 37
        };
        home.push(n % 3, envelope(scope(1 + n % 3), 2, n, len))
            .unwrap();
    }
    home.operate(admin(0), "remove", 2u32).unwrap();
    home.pass(72 * HOUR_MS);
    home.commit_removing(0, vec![2]);
    home.call::<Candidacy>(admin(0), "commit", update(4, 4))
        .unwrap();
    let voided: Voted = home.call(sync(0), "nack", (4u64, [0u8; 64])).unwrap();
    assert!(matches!(voided.verdict, Some(Verdict::Void(_))));
    for n in 1..=3 {
        home.call::<u64>(sync(1), "acknowledge", (scope(n), 5u64, [n; 32]))
            .unwrap();
    }
    let expires = home.now() + DAY;
    home.call::<u64>(
        sync(1),
        "put",
        ((Recipient::Devices, [5u8; 16]), (expires, vec![5u8; 300])),
    )
    .unwrap();
    let contested = home.operate(admin(0), "remove", 1u32).unwrap();
    home.operate(admin(1), "veto", contested).unwrap();
    let cancelled = home.operate(KIT, "remove", 0u32).unwrap();
    home.operate(admin(0), "veto", cancelled).unwrap();
    home.operate(KIT, "remove", 1u32).unwrap_err();
    home.operate(admin(1), "add", device(7)).unwrap();
    let before = everything(&home);
    assert!(before.log.len() > 10 && before.scopes.iter().all(|read| read.len() == 10));
    assert_eq!(
        before.operations.len(),
        2,
        "the contested removal and the add"
    );

    // The next version, installed over the same instance.
    let next = derived("personal-next");
    // On the node itself, at the batch time the reads above were made at.
    let now = home.now();
    let node = home.world().node_mut(crate::common::AGENT);
    node.add(&next.actor);
    let install = Input::Admin(Admin::Install {
        instance: PERSONAL,
        derivation: next.derivation(),
        roles: vec![(b"homes".to_vec(), 1)],
        target: Target::Vos,
        space: SpaceId::NONE,
        clock: WindowClock::DEFAULT,
    });
    let installed = node.batch(now, vec![install]);
    assert!(matches!(ran(&installed.steps[0]).outcome, Outcome::Done(_)));
    let version: u32 = home.query(STRANGER, "version", ()).unwrap();
    assert_eq!(version, 2);
    assert_eq!(everything(&home), before);

    let epoch = home.overview().confirmed;
    home.push(0, envelope(scope(1), epoch, 0xee, 400)).unwrap();
    let taken: Candidacy = home
        .call(admin(0), "commit", update(epoch + 1, 0xee))
        .unwrap();
    home.confirm_all(epoch + 1, &taken.set);
}
