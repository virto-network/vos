//! The space's representative (`agent/representative`) on the default
//! agent, against the testkit: an agent's report, sent as the agent's
//! report step sends it, stores the agent's root in the representative's
//! committed map under exactly the key a read's path names
//! ([`vos_wire::served::representative_row`]) as a bare 32-byte value, as
//! a kernel's prologue checks it; an ask under the key its node reads, and
//! the window as one a read waits on; the rows of old windows gone; and no
//! program's call writes any of it.

use vos_testkit::Testkit;
use vos_testkit::programs::{representative_package, table_tag};
use vos_wire::abi::cap::Target;
use vos_wire::batch::{Body, Input, Message};
use vos_wire::ids::{AgentId, MapId, MethodId, Principal, derive_id};
use vos_wire::keys::{self, Transform};
use vos_wire::records::unversioned;
use vos_wire::served::{
    ASKED_TAG, AgentRoot, REPRESENTATIVE, REPRESENTATIVE_ASKED, REPRESENTATIVE_ROOTS,
    REPRESENTATIVE_TAG, representative_ask, representative_row,
};
use vos_wire::vos_anchor::{MIN_LENGTH_MS, RootKind};
use vos_wire::{Encode, SpaceId, WindowClock};

use crate::common::{Node, agrees, install_in, ran};

const CLOCK: WindowClock = WindowClock {
    origin_ms: MIN_LENGTH_MS / 5,
    length_ms: MIN_LENGTH_MS,
};

/// A time in the representative's window `window`.
fn at(window: u64) -> u64 {
    CLOCK.boundary(window).unwrap() - 1
}

const SPACE: SpaceId = SpaceId([0x5a; 32]);

/// The representative installed as `AGENT`'s instance 0, in a node and the
/// model.
fn representative() -> (Node, Testkit) {
    let package = representative_package();
    let derived = vos_pvm_compiler::derive(&package).unwrap();
    let mut node = Node::new();
    let (kit, installed) = install_in(
        &mut node,
        (SPACE, CLOCK),
        Target::Vos,
        REPRESENTATIVE,
        &package,
        &derived,
    );
    assert!(
        matches!(
            ran(&installed.steps[0]).outcome,
            vos_wire::result::Outcome::Done(_)
        ),
        "{:?}",
        ran(&installed.steps[0]).outcome
    );
    (node, kit)
}

/// A report of `root` at `window`, as an agent's report step sends it.
fn report_body(window: u64, root: [u8; 32]) -> Body {
    Body::Report(AgentRoot {
        kind: RootKind::Space as u8,
        window,
        root,
    })
}

/// Agent `from`'s report of `root` at `window`, as its report step sends
/// it.
fn report(from: AgentId, sequence: u64, window: u64, root: [u8; 32]) -> Input {
    Input::Message(Message {
        from,
        sequence,
        body: report_body(window, root),
    })
}

/// The ask of `agent` at `window`, as the representative's node reads it:
/// a row of its committed map `asked`.
fn asked(window: u64, agent: AgentId) -> Vec<u8> {
    let raw = [&window.to_be_bytes()[..], &agent.0.to_be_bytes()].concat();
    let map = MapId {
        instance: REPRESENTATIVE,
        tag: ASKED_TAG,
        transform: Transform::Ordered,
    };
    keys::committed(&map, &Transform::Ordered.apply(&raw))
}

/// The committed rows of `node`'s state.
fn committed(node: &Node) -> Vec<Vec<u8>> {
    node.state
        .keys()
        .filter(|key| keys::is_committed(key))
        .cloned()
        .collect()
}

/// The representative's names are the constants the agents and the node
/// use, and a report is stored as a read proves it ([`reports_are_stored`],
/// [`old_windows_go`]); no call stores one ([`no_call_writes_a_report`]).
#[test]
fn a_report_is_stored_as_a_read_proves_it() {
    let (mut node, mut kit) = representative();
    assert_eq!(table_tag(REPRESENTATIVE_ROOTS), REPRESENTATIVE_TAG);
    assert_eq!(table_tag(REPRESENTATIVE_ASKED), ASKED_TAG);

    let (a, b) = (AgentId(0x0100_0007), AgentId(0x0200_0003));
    reports_are_stored(&mut node, &mut kit, a, b);
    old_windows_go(&mut node, a, b);
    no_call_writes_a_report(&mut node, a);
}

/// The stored value under `key`, unversioned.
fn value(node: &Node, key: &[u8]) -> Option<Vec<u8>> {
    let stored = node.get(key)?;
    let (_, value) = unversioned(&stored)?;
    Some(value.to_vec())
}

/// A report stores the reporting agent's root under
/// `representative_row(agent, Space, w)`, its value the bare root, an ask
/// under `w ‖ agent`, and the latest window reported as the one a read
/// waits on, which the representative's apply cuts. A report of a window
/// at or before the sender's last, or two past the representative's open
/// window, stores nothing. The model agrees on each step.
fn reports_are_stored(node: &mut Node, kit: &mut Testkit, a: AgentId, b: AgentId) {
    let inputs = vec![
        report(a, 1, 5, [5; 32]),
        report(b, 1, 5, [6; 32]),
        report(a, 2, 6, [7; 32]),
        report(b, 2, 5, [9; 32]),
        report(b, 3, 7, [9; 32]),
    ];
    let result = node.batch(at(5), inputs.clone());
    kit.batch(at(5), [0; 32]);
    for (index, (step, input)) in result.steps.iter().zip(&inputs).enumerate() {
        let Input::Message(message) = input else {
            unreachable!()
        };
        let expected = kit.message(message.from, &message.body);
        let run = ran(step);
        assert_eq!(run.outcome, vos_wire::result::Outcome::Done(Vec::new()));
        agrees(index, run, &expected);
    }
    assert_eq!(
        value(node, &representative_row(a, RootKind::Space, 5)),
        Some(vec![5; 32])
    );
    assert_eq!(
        value(node, &representative_row(b, RootKind::Space, 5)),
        Some(vec![6; 32])
    );
    assert_eq!(
        value(node, &representative_row(a, RootKind::Space, 6)),
        Some(vec![7; 32])
    );
    assert!(node.get(&asked(5, a)).is_some());
    assert!(node.get(&asked(5, b)).is_some());
    assert!(node.get(&asked(6, a)).is_some());
    assert_eq!(asked(5, a), representative_ask(5, a));
    assert_eq!(
        node.value::<u64>(&keys::reading()),
        Some(6),
        "the latest window reported"
    );
    assert_eq!(
        value(node, &representative_row(b, RootKind::Space, 7)),
        None,
        "two past the open window"
    );
    assert_eq!(
        value(node, &representative_row(b, RootKind::Space, 5)),
        Some(vec![6; 32]),
        "a window reported already"
    );
}

/// Window 8: a later report of `a` drops its rows of windows before
/// `w − 2` and its asks with them, never another agent's.
fn old_windows_go(node: &mut Node, a: AgentId, b: AgentId) {
    node.batch(at(7), vec![report(a, 3, 8, [8; 32])]);
    assert_eq!(
        value(node, &representative_row(a, RootKind::Space, 5)),
        None
    );
    assert!(value(node, &representative_row(a, RootKind::Space, 6)).is_some());
    assert!(value(node, &representative_row(b, RootKind::Space, 5)).is_some());
    assert!(node.get(&asked(5, a)).is_none());
    assert!(node.get(&asked(8, a)).is_some());
}

/// A client's call, and a program's call as any agent's message carries it,
/// of a method named `report` store nothing: the representative has none.
fn no_call_writes_a_report(node: &mut Node, a: AgentId) {
    let before = committed(node);
    let method = MethodId(derive_id("vos/method/", "report"));
    let arguments = AgentRoot {
        kind: 0,
        window: 9,
        root: [9; 32],
    }
    .encode();
    let client = Input::Request(vos_wire::batch::Request {
        session: vos_wire::ids::Session {
            key: [1; 32],
            name: [0; 16],
            t0: at(8),
        },
        sequence: 1,
        caller: Principal::Client([1; 32]),
        instance: REPRESENTATIVE,
        method,
        arguments: arguments.clone(),
    });
    let call = Input::Message(Message {
        from: a,
        sequence: 4,
        body: Body::Call {
            instance: REPRESENTATIVE,
            method,
            arguments,
            awaiting: None,
        },
    });
    let result = node.batch(at(8), vec![client, call]);
    for step in &result.steps {
        if let vos_wire::result::Step::Ran(run) = step {
            assert!(run.committed.is_empty());
        }
    }
    assert!(
        node.get(&representative_row(a, RootKind::Space, 9))
            .is_none()
    );
    assert_eq!(committed(node), before);
    assert!(node.get(&asked(9, a)).is_none());
}

/// A row of a window's close that does not decode is quarantined, the
/// step going on (S30): the representative holding a sender's last report
/// that does not decode moves it aside under `keys::quarantined`, its
/// bytes kept, and stores the report as the sender's first. An agent
/// whose mark of its last report does not decode moves it aside too, and
/// reports. The model agrees on each step.
#[test]
fn a_row_that_does_not_decode_is_quarantined() {
    let (mut node, mut kit) = representative();
    let a = AgentId(0x0100_0007);
    let corrupt = vec![1, 2, 3];
    for key in [keys::reports(a), keys::reported()] {
        node.state
            .insert(key.clone(), vos_wire::records::stored(&corrupt));
        kit.set_row(key, corrupt.clone());
    }
    let inputs = vec![
        report(a, 1, 5, [5; 32]),
        Input::Report {
            to: AgentId(0x0900_0000),
            window: 4,
            root: [4; 32],
        },
    ];
    let result = node.batch(at(5), inputs);
    kit.batch(at(5), [0; 32]);
    let stored = kit.message(a, &report_body(5, [5; 32]));
    agrees(0, ran(&result.steps[0]), &stored);
    let reported = kit.report(AgentId(0x0900_0000), 4, [4; 32]);
    agrees(1, ran(&result.steps[1]), &reported);
    for key in [keys::reports(a), keys::reported()] {
        assert_eq!(node.get(&keys::quarantined(&key)), Some(corrupt.clone()));
    }
    assert_eq!(node.value::<u64>(&keys::reports(a)), Some(5));
    assert_eq!(
        value(&node, &representative_row(a, RootKind::Space, 5)),
        Some(vec![5; 32])
    );
    assert_eq!(
        node.value::<(u64, AgentId)>(&keys::reported()),
        Some((4, AgentId(0x0900_0000)))
    );
    assert_eq!(ran(&result.steps[1]).messages.len(), 1, "reported");
}
