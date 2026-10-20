//! The space's representative (`agent/representative`) on the default
//! agent, against the testkit: an agent's report, sent as the agent's
//! report step sends it, stores the agent's root in the representative's
//! committed map under exactly the key a read's path names
//! ([`vos_wire::served::representative_row`]) as a bare 32-byte value, as
//! a kernel's prologue checks it; an ask under the key its node reads; the
//! rows of old windows gone; and no program's call writes any of it.

use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, representative_package, table_tag};
use vos_wire::abi::cap::Target;
use vos_wire::batch::{Admin, Body, Input, Message};
use vos_wire::ids::{AgentId, MethodId, Principal, derive_id};
use vos_wire::keys::{self, Transform};
use vos_wire::records::unversioned;
use vos_wire::served::{
    ASKED_TAG, AgentRoot, REPRESENTATIVE, REPRESENTATIVE_ASKED, REPRESENTATIVE_ROOTS,
    REPRESENTATIVE_TAG, representative_ask, representative_row,
};
use vos_wire::vos_anchor::{MIN_LENGTH_MS, RootKind};
use vos_wire::{Encode, SpaceId, WindowClock};

const CLOCK: WindowClock = WindowClock {
    origin_ms: MIN_LENGTH_MS / 5,
    length_ms: MIN_LENGTH_MS,
};

/// A time in the representative's window `window`.
fn at(window: u64) -> u64 {
    CLOCK.boundary(window).unwrap() - 1
}

use crate::common::{AGENT, Node, ran};

const SPACE: SpaceId = SpaceId([0x5a; 32]);

/// The representative installed as `AGENT`'s instance 0, in a node and the
/// model.
fn representative() -> (Node, Testkit) {
    let package = representative_package();
    let derived = vos_pvm_compiler::derive(&package).unwrap();
    let mut node = Node::new();
    node.add(&derived.actor);
    let clock = CLOCK;
    let install = Input::Admin(Admin::Install {
        instance: REPRESENTATIVE,
        derivation: derivation(&package, &derived),
        roles: vec![],
        target: Target::Vos,
        space: SPACE,
        clock,
    });
    let installed = node.batch(0, vec![install]);
    assert!(
        matches!(
            ran(&installed.steps[0]).outcome,
            vos_wire::result::Outcome::Done(_)
        ),
        "{:?}",
        ran(&installed.steps[0]).outcome
    );
    let mut kit = Testkit::new(AGENT);
    kit.install_derived_in((SPACE, clock), Target::Vos, REPRESENTATIVE, &derived, &[])
        .unwrap();
    kit.version = node.version;
    (node, kit)
}

/// Agent `from`'s report of `root` at `window`, `pending` or not, as its
/// report step sends it.
fn report(from: AgentId, sequence: u64, window: u64, root: [u8; 32], pending: bool) -> Input {
    Input::Message(Message {
        from,
        sequence,
        body: Body::Report(AgentRoot {
            kind: RootKind::Space as u8,
            window,
            root,
            pending,
        }),
    })
}

/// The ask of `agent` at `window`, as the representative's node reads it.
fn asked(window: u64, agent: AgentId) -> Vec<u8> {
    let raw = [&window.to_be_bytes()[..], &agent.0.to_be_bytes()].concat();
    [
        keys::table_rows(REPRESENTATIVE, ASKED_TAG, Transform::Ordered),
        Transform::Ordered.apply(&raw),
    ]
    .concat()
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
/// use; a report stores the reporting agent's root under
/// `representative_row(agent, Space, w)`, its value the bare root, and an
/// ask under `w ‖ agent`; a later report of the agent drops its rows of
/// windows before `w − 2` and its asks with them, never another agent's.
/// A report of a window at or before the sender's last, or two past the
/// representative's open window, stores nothing. The model agrees on each
/// step.
#[test]
fn a_report_is_stored_as_a_read_proves_it() {
    let (mut node, mut kit) = representative();
    assert_eq!(table_tag(REPRESENTATIVE_ROOTS), REPRESENTATIVE_TAG);
    assert_eq!(table_tag(REPRESENTATIVE_ASKED), ASKED_TAG);

    let (a, b) = (AgentId(0x0100_0007), AgentId(0x0200_0003));
    let inputs = vec![
        report(a, 1, 5, [5; 32], true),
        report(b, 1, 5, [6; 32], true),
        report(a, 2, 6, [7; 32], false),
        report(b, 2, 5, [9; 32], false),
        report(b, 3, 7, [9; 32], false),
    ];
    let result = node.batch(at(5), inputs.clone());
    kit.batch(at(5), [0; 32]);
    for (step, input) in result.steps.iter().zip(&inputs) {
        let Input::Message(message) = input else {
            unreachable!()
        };
        let expected = kit.message(message.from, &message.body);
        let run = ran(step);
        assert_eq!(run.outcome, vos_wire::result::Outcome::Done(Vec::new()));
        assert_eq!(run.outcome, expected.outcome);
        assert_eq!(run.writes, expected.writes);
        assert_eq!(run.committed, expected.committed);
    }
    let value = |node: &Node, key: &[u8]| {
        let stored = node.get(key)?;
        let (_, value) = unversioned(&stored)?;
        Some(value.to_vec())
    };
    assert_eq!(
        value(&node, &representative_row(a, RootKind::Space, 5)),
        Some(vec![5; 32])
    );
    assert_eq!(
        value(&node, &representative_row(b, RootKind::Space, 5)),
        Some(vec![6; 32])
    );
    assert_eq!(
        value(&node, &representative_row(a, RootKind::Space, 6)),
        Some(vec![7; 32])
    );
    assert!(node.get(&asked(5, a)).is_some());
    assert!(node.get(&asked(5, b)).is_some());
    assert!(node.get(&asked(6, a)).is_none(), "not pending");
    assert_eq!(asked(5, a), representative_ask(5, a));
    assert_eq!(
        value(&node, &representative_row(b, RootKind::Space, 7)),
        None,
        "two past the open window"
    );
    assert_eq!(
        value(&node, &representative_row(b, RootKind::Space, 5)),
        Some(vec![6; 32]),
        "a window reported already"
    );

    // Window 8: `a`'s rows before window 6 go, and every ask of them.
    node.batch(at(7), vec![report(a, 3, 8, [8; 32], true)]);
    assert_eq!(
        value(&node, &representative_row(a, RootKind::Space, 5)),
        None
    );
    assert!(value(&node, &representative_row(a, RootKind::Space, 6)).is_some());
    assert!(value(&node, &representative_row(b, RootKind::Space, 5)).is_some());
    assert!(node.get(&asked(5, a)).is_none());
    assert!(node.get(&asked(8, a)).is_some());

    // A client's call, and a program's call as any agent's message carries
    // it, of a method named `report` store nothing: the representative has
    // none.
    let before = committed(&node);
    let method = MethodId(derive_id("vos/method/", "report"));
    let arguments = AgentRoot {
        kind: 0,
        window: 9,
        root: [9; 32],
        pending: true,
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
    assert_eq!(committed(&node), before);
    assert!(node.get(&asked(9, a)).is_none());
}
