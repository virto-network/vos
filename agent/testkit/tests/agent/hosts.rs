//! The hosts the agent runs on: a VOS node's, with a pool and applied
//! state, and a JAM node's, with neither, and the host calls every program
//! makes.

use vos_pvm::ExitReason;
use vos_testkit::programs::{agent, method};
use vos_wire::abi::surface;
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::AgentId;
use vos_wire::ingress::Grant;

use crate::common::{
    ALICE, Actors, BOB, COUNTER, LEDGER, MINTER, Node, OUTER_GAS, Sessions, counter_only, done,
    install,
};

/// Every program calls only what a JAM node serves, or what has a
/// fallback there (`abi::surface`): the default agent, the test actors and
/// the attestable program, every `ecalli` in them, reachable or not.
#[test]
fn every_program_calls_only_its_surface() {
    let calls = |blob: &[u8]| vos_pvm::spi::inspect_standard_program_host_calls(blob).unwrap();
    let mut seen: Vec<u64> = calls(&agent());
    seen.sort_unstable();
    seen.dedup();
    for call in &seen {
        assert!(surface::agent(*call).is_some(), "the agent calls {call:#x}");
    }
    assert!(
        seen.iter()
            .any(|call| surface::agent(*call) == Some(surface::OnJam::Loader)),
        "the agent instantiates: the check sees its calls"
    );
    let actors = Actors::load();
    for (name, blob) in [
        ("counter", &actors.counter),
        ("ledger", &actors.ledger),
        ("caller", &actors.caller),
    ] {
        for call in calls(blob) {
            assert!(surface::actor(call), "{name} calls {call:#x}");
        }
    }
    for call in calls(&actors.checksum) {
        assert!(surface::attestable(call), "checksum calls {call:#x}");
    }
}

/// Batches that read no state refine on a VOS host (the pool, applied
/// state) and on a JAM host (no pool, no state, no precompiles, actors
/// from preimages) to the same work result, which both accumulate to the
/// same storage. No request or message appears: their session and pair
/// marks are applied state, which this host cannot read.
#[test]
fn vos_and_jam_hosts_agree_on_batches_that_read_no_state() {
    let actors = Actors::load();
    let mut vos = Node::new();
    let mut jam = Node::with(false, false);
    let mut add = |blob: &[u8]| {
        let hash = vos.add(blob);
        assert_eq!(jam.add(blob), hash);
        hash
    };
    let counter = add(&actors.counter);
    let ledger = add(&actors.ledger);
    let checksum = add(&actors.checksum);
    let audit = method(&actors.ledger, "checksum");
    let batches = vec![
        vec![
            install(COUNTER, counter),
            Input::Admin(Admin::Install {
                instance: LEDGER,
                program: ledger,
                attestables: vec![(audit, checksum)],
                roles: vec![(b"minter".to_vec(), MINTER)],
            }),
            Input::Admin(Admin::SetRole(Grant {
                principal: ALICE,
                role: Some(MINTER),
            })),
        ],
        vec![
            Input::Ack {
                to: AgentId(5),
                sequence: 1,
            },
            Input::Admin(Admin::SetRole(Grant {
                principal: ALICE,
                role: None,
            })),
            Input::Admin(Admin::SetRole(Grant {
                principal: BOB,
                role: Some(MINTER),
            })),
        ],
    ];
    for (time, inputs) in batches.into_iter().enumerate() {
        let work = vos.seeded_work(time as u64 + 1, [time as u8; 32], inputs);
        let on_vos = vos.refine(&work);
        let on_jam = jam.refine(&work);
        assert_eq!(on_vos, on_jam, "batch {time}");
        vos.accumulate(&on_vos);
        jam.accumulate(&on_jam);
        vos.version += 1;
        jam.version += 1;
        assert_eq!(vos.state, jam.state, "storage after batch {time}");
    }
}

#[test]
fn without_a_pool_the_loader_builds_the_machines() {
    let actors = Actors::load();
    let mut node = Node::with(false, true);
    let counter = node.add(&actors.counter);
    let increment = actors.method(COUNTER, "increment");
    let mut sessions = Sessions::new();
    let first = node.batch(
        1,
        vec![
            install(COUNTER, counter),
            sessions.request(ALICE, COUNTER, increment, 5u64),
        ],
    );
    assert_eq!(done::<u64>(&first.steps[1]), 5);
    let second = node.batch(2, vec![sessions.request(ALICE, COUNTER, increment, 2u64)]);
    assert_eq!(
        done::<u64>(&second.steps[0]),
        7,
        "applied state carries over"
    );
}

#[test]
fn a_refine_that_cannot_read_state_produces_no_result() {
    // Admin inputs read no state: the install applies.
    let (actors, node) = counter_only(Node::with(false, false));
    let increment = actors.method(COUNTER, "increment");
    let mut sessions = Sessions::new();
    for time in [2, 3] {
        let work = node.work(
            time,
            vec![sessions.request(ALICE, COUNTER, increment, 5u64)],
        );
        assert_eq!(
            node.run_refine(&work, OUTER_GAS).exit,
            ExitReason::Panic,
            "no result computed on empty state"
        );
    }
}
