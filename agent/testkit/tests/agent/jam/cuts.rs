//! Window cuts on both hosts: one apply records them, so a VOS node and a
//! JAM package cut the same windows at the same versions; a package's
//! witness serves the agent's record (its target, space and clock) whole
//! whenever it serves any of it; and the default agent traps on a record
//! stored in part.

use super::*;
use vos_wire::{SpaceId, WindowClock};

const SPACE: SpaceId = SpaceId([0x5a; 32]);
/// The shortest windows a venue registers, the first boundary 90 s after
/// `T0`.
const CLOCK: WindowClock = WindowClock {
    origin_ms: T0 - 30_000,
    length_ms: vos_wire::vos_anchor::MIN_LENGTH_MS,
};

/// An install of `program` at `instance` for `target`, into `SPACE`.
fn in_space(target: Target, instance: InstanceId, program: ProgramHash) -> Input {
    Input::Admin(Admin::Install {
        instance,
        derivation: vos_testkit::programs::bare(program),
        roles: vec![],
        target,
        space: SPACE,
        clock: CLOCK,
    })
}

/// The cuts a node's state holds: each window's version.
fn cuts(node: &Node) -> BTreeMap<u64, u64> {
    let prefix = keys::cuts();
    node.state
        .range(prefix.clone()..)
        .take_while(|(key, _)| key.starts_with(&prefix))
        .map(|(key, value)| {
            let window = keys::cut_entry(key).expect("a cut row");
            let version = u64::decode(unstored(value).expect("stored")).unwrap().0;
            (window, version)
        })
        .collect()
}

/// How many of the agent's record rows a witness opens.
fn record_rows(witness: &[(Vec<u8>, Opened)]) -> usize {
    let record = [keys::target(), keys::space(), keys::clock()];
    witness
        .iter()
        .filter(|(key, _)| record.contains(key))
        .count()
}

/// Batches of an agent in a space, each run on a VOS node and as a JAM
/// package, which agree on every row (cuts among them): the install
/// records no cut; a batch exactly at `B_0` cuts window 0 at the version
/// before it; one whose time jumps three windows ahead cuts windows 1 to 3
/// at one version; one at the same time cuts nothing. Every package's
/// witness opens the agent's record whole or not at all, and a package
/// whose batch crosses a boundary opens it whole: its apply reads the
/// space and the clock to cut.
#[test]
fn vos_and_jam_cut_the_same_windows_and_witness_the_record_whole() {
    let actors = Actors::load();
    let mut paired = Paired::new(PvmBackend::Default, &programs(&actors), POLKAJAM_REFINE_GAS);
    let counter = ProgramHash::of(&actors.counter);
    let increment = actors.method(COUNTER, "increment");
    let installed = paired.batch(T0, vec![in_space(Target::Jam, COUNTER, counter)]);
    ran_or_refused(&installed.result);
    assert_eq!(record_rows(&installed.witness), 3, "the install's");
    assert!(cuts(&paired.vos).is_empty(), "the install cuts nothing");
    let boundary = |window| CLOCK.boundary(window).unwrap();
    let times = [
        (T0 + 1_000, false),
        (boundary(0) - 1, false),
        (boundary(0), true),
        (boundary(3) + 5, true),
        (boundary(3) + 5, false),
    ];
    let mut expected = BTreeMap::new();
    let mut mark = T0;
    for (time, crosses) in times {
        let before = paired.vos.version;
        let input = paired.request(ALICE, COUNTER, increment, 1u64);
        let ran = paired.batch(time, vec![input]);
        ran_or_refused(&ran.result);
        for window in 0..8 {
            let at = boundary(window);
            if mark < at && at <= time {
                expected.insert(window, before);
            }
        }
        mark = time;
        assert_eq!(cuts(&paired.vos), expected, "the cuts at {time}");
        let opened = record_rows(&ran.witness);
        assert!(opened == 0 || opened == 3, "{opened} of the record's rows");
        if crosses {
            assert_eq!(opened, 3, "a batch crossing a boundary reads the record");
        }
    }
    assert_eq!(expected, BTreeMap::from([(0, 3), (1, 4), (2, 4), (3, 4)]));
}

/// A record stored in part, one or two of the target, the space and the
/// clock without the rest, is corrupt: on every host, an install's step
/// over it traps (`Failure::Trapped`) and installs nothing.
#[test]
fn a_record_stored_in_part_traps_on_every_host() {
    let actors = Actors::load();
    let record = [
        (keys::target(), Target::Vos.encode()),
        (keys::space(), SPACE.encode()),
        (keys::clock(), CLOCK.encode()),
    ];
    for (target, jam) in [(Target::Vos, false), (Target::Jam, true)] {
        for held in 1..7u8 {
            let mut node = if jam { Node::jam(true) } else { Node::new() };
            let counter = node.add(&actors.counter);
            for (at, (key, value)) in record.iter().enumerate() {
                if held & (1 << at) != 0 {
                    node.state.insert(key.clone(), stored(value));
                }
            }
            let work = node.work(T0, vec![in_space(target, COUNTER, counter)]);
            let (result, _) = split_output(&node.refine(&work)).expect("a work result");
            let Step::Ran(run) = &result.steps[0] else {
                panic!("{target:?}: the install ran");
            };
            assert_eq!(
                run.outcome,
                Outcome::failed(vos_wire::abi::Failure::Trapped),
                "{target:?}: a record of rows {held:03b} alone"
            );
            assert!(run.writes.is_empty(), "nothing installed");
        }
    }
}
