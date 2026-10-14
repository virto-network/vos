//! The hosts the agent runs on: a VOS node's, with a pool, applied state
//! and precompiles computed, and a JAM node's, with none of them and
//! PolkaJam's prices; and the host calls every program makes. A JAM
//! package, its state witnessed, against a VOS node: `jam`.

use vos_pvm::ExitReason;
use vos_testkit::programs::agent;
use vos_wire::abi::{self, cap, surface};
use vos_wire::batch::{Admin, Input, Message, Work};
use vos_wire::ids::AgentId;
use vos_wire::ingress::Grant;
use vos_wire::result::WorkResult;
use vos_wire::{Decode, Encode};

use crate::common::{
    ALICE, Actors, BOB, CALLER, COUNTER, LEDGER, MINTER, Node, OUTER_GAS, Sessions, counter_only,
    done, install, ran_done,
};

/// Every program calls only what a JAM node serves, or what has a
/// fallback there (`abi::surface`): the default agent, the test actors and
/// the attestable and workflow programs, every `ecalli` in them, reachable
/// or not.
#[test]
fn every_program_calls_only_its_surface() {
    let calls = |blob: &[u8]| vos_pvm::spi::inspect_standard_program_host_calls(blob).unwrap();
    let mut seen: Vec<u64> = calls(&agent());
    seen.sort_unstable();
    seen.dedup();
    for call in &seen {
        assert!(surface::agent(*call).is_some(), "the agent calls {call:#x}");
    }
    for (kind, name) in [
        (surface::OnJam::Loader, "instantiates"),
        (surface::OnJam::Software, "computes BLAKE2b"),
    ] {
        assert!(
            seen.iter().any(|call| surface::agent(*call) == Some(kind)),
            "the agent {name}: the check sees its calls"
        );
    }
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
    for call in calls(&actors.tally) {
        assert!(surface::workflow(call), "tally calls {call:#x}");
    }
    // The shop's workflows: each that pauses calls an operation only a
    // workflow may use, and each that compresses calls the precompile.
    let pauses = [abi::op::REQUEST, abi::op::RESULT, abi::op::SLEEP];
    let computes = [
        "chain",
        "grind",
        "grind_whole",
        "settle",
        "relay",
        "stuck",
        "press",
    ];
    let compresses = ["digest", "press"];
    for name in crate::workflows::FLOWS {
        let calls = calls(&vos_testkit::programs::actor(name));
        for call in &calls {
            assert!(surface::workflow(*call), "{name} calls {call:#x}");
        }
        assert_eq!(
            calls.iter().any(|call| pauses.contains(call)),
            !computes.contains(&name),
            "{name} pauses: the check sees its calls"
        );
        assert_eq!(
            calls.contains(&abi::precompile::BLAKE2B_COMPRESS),
            compresses.contains(&name),
            "{name} compresses"
        );
    }
    for call in calls(&vos_testkit::programs::actor("shop")) {
        assert!(surface::actor(call), "shop calls {call:#x}");
    }
}

/// The JAM-only host charges PolkaJam's prices where they differ from the
/// Gray Paper's base, as the probe in `spikes/sj-jam-b` measured them:
/// `gas` 48, `log` 1,000 and answering `WHAT`, a call it does not serve
/// 1,000, a segment's `fetch` 171 and an `export` 3,521. The runtime's
/// tests measure each charge. Its segments are the agent's.
#[test]
fn the_jam_host_charges_polkajams_prices() {
    use vos_pvm::refine_host::{MAX_EXPORTS, SEGMENT, jam_gas};
    assert_eq!(
        (jam_gas::GAS, jam_gas::LOG, jam_gas::UNSERVED),
        (48, 1_000, 1_000)
    );
    assert_eq!(
        (jam_gas::fetch(SEGMENT as u64), jam_gas::EXPORT),
        (171, 3_521)
    );
    assert_eq!(SEGMENT, vos_wire::package::SEGMENT);
    assert_eq!(MAX_EXPORTS as usize, vos_wire::package::MAX_SEGMENTS);
}

/// The agent serves its machines the precompiles a VOS node serves the
/// agent, each at the node's price; every other id among the precompiles
/// it leaves unserved, as a JAM node does.
#[test]
fn the_agent_serves_the_precompiles_a_node_does_at_its_price() {
    for id in surface::PRECOMPILES {
        assert_eq!(
            abi::precompile::price(id),
            vos_pvm::precompile::price(id),
            "{id:#x}"
        );
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
    let mut jam = Node::jam(false);
    let counter = vos.add(&actors.counter);
    for program in [
        &actors.counter,
        &actors.ledger,
        &actors.checksum,
        &actors.tally,
    ] {
        jam.add(program);
    }
    let batches = vec![
        vec![
            install(COUNTER, counter),
            actors.install_ledger(&mut vos),
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

/// Batches that run actors refine on a VOS host and on a JAM host to the
/// same work result, byte for byte, and accumulate to the same storage:
/// requests and a message, nested calls, an attestable, and precompile
/// calls, which the agent serves at the same price on both, though their
/// outer gas differs (in software on JAM); and a batch its budget cuts
/// short, at the same step on both, since the agent dispatches by its own
/// accounting. The JAM host reads applied state here, as a package's
/// witness gives it (`jam`); without one a batch that reads state has no
/// result there (`a_refine_that_cannot_read_state_produces_no_result`).
#[test]
fn vos_and_jam_hosts_agree_on_batches_that_run_actors() {
    let actors = Actors::load();
    let mut vos = Node::new();
    let mut jam = Node::jam(true);
    let mut add = |blob: &[u8]| {
        let hash = vos.add(blob);
        assert_eq!(jam.add(blob), hash);
        hash
    };
    let counter = add(&actors.counter);
    let caller = add(&actors.caller);
    for program in [&actors.ledger, &actors.checksum, &actors.tally] {
        add(program);
    }
    let mut sessions = Sessions::new();
    let method = |instance, name| actors.method(instance, name);
    let hash = |sessions: &mut Sessions, rounds: u32| {
        sessions.request(
            ALICE,
            COUNTER,
            method(COUNTER, "hash"),
            (vec![7u8; 300], rounds),
        )
    };
    let installs = vec![
        install(COUNTER, counter),
        actors.install_ledger(&mut vos),
        install(CALLER, caller),
        Input::Admin(Admin::SetRole(Grant {
            principal: ALICE,
            role: Some(MINTER),
        })),
    ];
    let actor_steps = vec![
        sessions.request(ALICE, COUNTER, method(COUNTER, "increment"), 5u64),
        hash(&mut sessions, 4),
        sessions.request(ALICE, LEDGER, method(LEDGER, "mint"), (1u64, 100u64)),
        sessions.request(ALICE, LEDGER, method(LEDGER, "audit"), vec![1u64, 2, 3]),
        sessions.request(
            ALICE,
            CALLER,
            method(CALLER, "pay"),
            ((LEDGER.0, 1u64), (2u64, 40u64)),
        ),
        Input::Message(Message {
            from: AgentId(5),
            sequence: 1,
            body: vos_wire::batch::Body::Call {
                instance: COUNTER,
                method: method(COUNTER, "hash"),
                arguments: (vec![1u8; 1000], 2u32).encode(),
                awaiting: None,
            },
        }),
    ];
    let hashes: Vec<Input> = (0..10).map(|_| hash(&mut sessions, 3)).collect();
    // Room for a few of the hashes after the first, each 50M of limit.
    let short = 52_000_000;
    let batches = [
        (installs, OUTER_GAS),
        (actor_steps, OUTER_GAS),
        (hashes, short),
    ];
    for (time, (inputs, budget)) in batches.into_iter().enumerate() {
        let time = time as u64 + 1;
        let work = vos.budgeted_work(time, [time as u8; 32], budget, inputs);
        let (on_vos, vos_gas) = refined(&vos, &work, budget);
        let (on_jam, jam_gas) = refined(&jam, &work, budget);
        assert_eq!(on_vos, on_jam, "batch {time}");
        let result = WorkResult::decode(&on_vos).unwrap().0;
        for step in &result.steps {
            ran_done(step);
        }
        if time > 1 {
            assert_ne!(
                vos_gas, jam_gas,
                "batch {time}: the hosts' outer gas differs"
            );
        }
        if time == 3 {
            assert!(
                !result.steps.is_empty() && result.steps.len() < 10,
                "the budget cuts the batch: {} steps",
                result.steps.len()
            );
        }
        vos.accumulate(&on_vos);
        jam.accumulate(&on_jam);
        vos.version += 1;
        jam.version += 1;
        assert_eq!(vos.state, jam.state, "storage after batch {time}");
    }
}

/// `work`'s result on `node`, refined with its budget's gas, and the gas
/// the refine used.
fn refined(node: &Node, work: &Work, gas: u64) -> (Vec<u8>, u64) {
    let invocation = node.run_refine(work, gas);
    assert_eq!(invocation.exit, ExitReason::Halt, "refine halts");
    let output = invocation.output_bounded(cap::OUTPUT).unwrap();
    (output, invocation.gas_used)
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
    let (actors, node) = counter_only(Node::jam(false));
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
