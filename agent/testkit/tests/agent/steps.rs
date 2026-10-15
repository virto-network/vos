//! A batch's steps: what each runs and writes, the caps it holds, the
//! calls it nests, the state it reads, how much of a batch a refine takes
//! on, and the testkit's answer for each.

use std::collections::BTreeMap;

use proptest::prelude::*;
use vos_pvm::ExitReason;
use vos_testkit::programs::{method, table_tag};
use vos_testkit::{Testkit, decode};
use vos_wire::abi::{Failure, Refusal, Rows, cap, code};
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::{InputRef, Outcome, WorkResult};
use vos_wire::{Decode, Encode, defaults};

mod kernels;
mod scans;

use crate::common::{
    AGENT, ALICE, Actors, BOB, CALLER, COUNTER, LEDGER, MINTER, Node, OUTER_GAS, Sessions, done,
    failed, install, ran, ran_done, refused, request, setup,
};

#[test]
fn a_failed_step_consumes_its_input_and_later_steps_see_earlier_writes() {
    let (actors, mut node, _, mut sessions) = setup();
    let increment = actors.method(COUNTER, "increment");
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, COUNTER, increment, 5u64),
            sessions.request(ALICE, COUNTER, increment, u64::MAX),
            sessions.request(ALICE, COUNTER, increment, 3u64),
        ],
    );
    assert_eq!(done::<u64>(&result.steps[0]), 5);
    assert_eq!(failed(&result.steps[1]), Failure::Handler);
    assert!(ran(&result.steps[1]).writes.is_empty());
    assert_eq!(done::<u64>(&result.steps[2]), 8, "the batch overlay");
    let (_, mark) = node.session(&Sessions::session(&ALICE)).unwrap();
    assert_eq!(mark.sequence, 3, "the failed request was consumed too");
    assert_eq!(
        node.query(ALICE, COUNTER, actors.method(COUNTER, "value"), ().encode()),
        Outcome::Done(8u64.encode())
    );
}

#[test]
fn kinds_and_unserved_ids_are_enforced() {
    let (actors, mut node, _, mut sessions) = setup();
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, COUNTER, actors.method(COUNTER, "sneaky"), ()),
            sessions.request(ALICE, COUNTER, actors.method(COUNTER, "unserved"), ()),
        ],
    );
    assert_eq!(
        failed(&result.steps[0]),
        Failure::Trapped,
        "a query may not write"
    );
    assert_eq!(done::<u64>(&result.steps[1]), code::WHAT);
    assert_eq!(
        node.query(
            ALICE,
            COUNTER,
            actors.method(COUNTER, "increment"),
            1u64.encode()
        ),
        Outcome::Failed {
            code: Failure::Unknown,
            detail: vec![],
        },
        "a query cannot run a command"
    );
}

#[test]
fn per_step_caps_fail_the_step_and_messages_reach_the_outbox() {
    let (actors, mut node, _, mut sessions) = setup();
    let fill = actors.method(COUNTER, "fill");
    let spam = actors.method(COUNTER, "spam");
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, COUNTER, fill, (5u32, 60_000u32)),
            sessions.request(ALICE, COUNTER, spam, (cap::MESSAGES as u32) + 1),
            sessions.request(ALICE, COUNTER, spam, 2u32),
        ],
    );
    assert_eq!(
        failed(&result.steps[0]),
        Failure::Cap,
        "writes past 256 KiB"
    );
    assert_eq!(failed(&result.steps[1]), Failure::Cap, "too many messages");
    assert_eq!(ran(&result.steps[2]).messages.len(), 2);
    assert!(node.get(&keys::outbox(AgentId(5), 1)).is_some());
    assert!(node.get(&keys::outbox(AgentId(5), 2)).is_some());
    let next: u64 = decode(&node.get(&keys::pair_out(AgentId(5))).unwrap()).unwrap();
    assert_eq!(next, 2);
}

#[test]
fn each_per_step_cap_holds_its_limit_and_fails_one_byte_past() {
    let (actors, mut node, _, mut sessions) = setup();
    let echo = actors.method(COUNTER, "echo");
    let large = actors.method(COUNTER, "large");
    let fill = actors.method(COUNTER, "fill");
    let put_and_scan = actors.method(COUNTER, "put_and_scan");
    // Past 16 KiB, a byte vector encodes with a 4-byte length.
    let bytes = |encoded: usize| encoded - 4;
    let rows = |transform| Rows::Table { tag: 7, transform }.register();
    let key = |transform, len: usize| (rows(transform), vec![vec![2u8; len]], None::<Vec<u8>>);
    let hashed = |len| key(Transform::Hashed, len);
    let ordered = |len| key(Transform::Ordered, len);
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, COUNTER, echo, vec![1u8; bytes(cap::REQUEST)]),
            sessions.request(ALICE, COUNTER, echo, vec![1u8; bytes(cap::REQUEST) + 1]),
            sessions.request(ALICE, COUNTER, large, bytes(cap::REPLY) as u32),
            sessions.request(ALICE, COUNTER, large, bytes(cap::REPLY) as u32 + 1),
            sessions.request(ALICE, COUNTER, fill, (1u32, bytes(cap::VALUE) as u32)),
            sessions.request(ALICE, COUNTER, fill, (1u32, bytes(cap::VALUE) as u32 + 1)),
            sessions.request(ALICE, COUNTER, put_and_scan, hashed(cap::KEY)),
            sessions.request(ALICE, COUNTER, put_and_scan, hashed(cap::KEY + 1)),
            sessions.request(ALICE, COUNTER, put_and_scan, ordered(cap::ORDERED_KEY)),
            sessions.request(ALICE, COUNTER, put_and_scan, ordered(cap::ORDERED_KEY + 1)),
        ],
    );
    for (at, past, what) in [
        (0, 1, "a request"),
        (2, 3, "a reply"),
        (4, 5, "a value"),
        (6, 7, "a key"),
        (8, 9, "an ordered table's key"),
    ] {
        assert!(
            matches!(ran(&result.steps[at]).outcome, Outcome::Done(_)),
            "{what} at its cap: {:?}",
            ran(&result.steps[at]).outcome
        );
        assert_eq!(
            failed(&result.steps[past]),
            Failure::Cap,
            "{what} past its cap"
        );
    }
}

#[test]
fn an_ack_clears_the_outbox_through_its_sequence() {
    let (actors, mut node, _, mut sessions) = setup();
    let spam = actors.method(COUNTER, "spam");
    node.batch(1, vec![sessions.request(ALICE, COUNTER, spam, 3u32)]);
    let to = AgentId(5);
    let pending = |node: &Node| -> Vec<u64> {
        (1..=3)
            .filter(|sequence| node.get(&keys::outbox(to, *sequence)).is_some())
            .collect()
    };
    let acked = |node: &Node| -> u64 { decode(&node.get(&keys::acked(to)).unwrap()).unwrap() };
    assert_eq!(pending(&node), [1, 2, 3]);
    let result = node.batch(
        2,
        vec![
            Input::Ack { to, sequence: 2 },
            Input::Ack { to, sequence: 1 },
        ],
    );
    for step in &result.steps {
        assert!(
            matches!(ran(step).outcome, Outcome::Done(_)),
            "an ack is never refused"
        );
    }
    assert_eq!(pending(&node), [3]);
    assert_eq!(acked(&node), 2, "a stale ack changes nothing");
    node.batch(3, vec![Input::Ack { to, sequence: 99 }]);
    assert!(pending(&node).is_empty());
    assert_eq!(acked(&node), 3, "an ack stops at what was sent");
}

#[test]
fn roles_nested_calls_cycles_and_attests() {
    let (actors, mut node, _, mut sessions) = setup();
    let result = node.batch(
        1,
        vec![
            sessions.request(BOB, LEDGER, actors.method(LEDGER, "mint"), (1u64, 10u64)),
            sessions.request(ALICE, LEDGER, actors.method(LEDGER, "mint"), (1u64, 100u64)),
            sessions.request(
                ALICE,
                CALLER,
                actors.method(CALLER, "pay"),
                ((LEDGER.0, 1u64), (2u64, 40u64)),
            ),
            sessions.request(ALICE, CALLER, actors.method(CALLER, "recurse"), ()),
            sessions.request(ALICE, LEDGER, actors.method(LEDGER, "audit"), vec![1u64, 2]),
            sessions.request(ALICE, CALLER, actors.method(CALLER, "relay"), LEDGER.0),
        ],
    );
    assert_eq!(failed(&result.steps[0]), Failure::Forbidden);
    assert_eq!(done::<u64>(&result.steps[1]), 100);
    assert_eq!(done::<u64>(&result.steps[2]), 40);
    let instances: Vec<_> = ran(&result.steps[2])
        .instances
        .iter()
        .map(|entry| entry.instance)
        .collect();
    assert_eq!(instances, [CALLER, LEDGER]);
    assert_eq!(failed(&result.steps[3]), Failure::Cycle);
    assert_eq!(ran(&result.steps[4]).attests.len(), 1);
    assert!(done::<bool>(&result.steps[5]));
    assert!(ran(&result.steps[5]).messages.is_empty());
}

#[test]
fn a_call_that_cannot_get_a_machine_fails_the_step() {
    let actors = Actors::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    let caller = node.add(&actors.caller);
    let installs: Vec<Input> = (100..170)
        .map(|instance| install(InstanceId(instance), caller))
        .collect();
    node.batch(0, installs);
    for instance in 100..170 {
        kit.install(InstanceId(instance), &actors.caller, &[], &[])
            .unwrap();
    }
    let hop = actors.method(CALLER, "hop");
    let mut sessions = Sessions::new();
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, InstanceId(100), hop, (101u32, 10u32)),
            sessions.request(ALICE, InstanceId(100), hop, (101u32, 69u32)),
        ],
    );
    assert_eq!(done::<u32>(&result.steps[0]), 10);
    assert_eq!(failed(&result.steps[1]), Failure::Depth);
    kit.batch(1, [0; 32]);
    let deep = kit.command(ALICE, InstanceId(100), hop, &(101u32, 10u32).encode());
    assert_eq!(&deep.outcome, &ran(&result.steps[0]).outcome);
    let deeper = kit.command(ALICE, InstanceId(100), hop, &(101u32, 69u32).encode());
    assert_eq!(&deeper.outcome, &ran(&result.steps[1]).outcome);
    assert_eq!(deeper.gas_used, ran(&result.steps[1]).gas_used);
}

/// A refine dispatches by its own accounting of its batch's budget, never
/// by the gas it reads: from a budget under a handler's limit up, every
/// refine halts with a prefix of the batch, longer as the budget grows, and
/// the same prefix whatever gas it has beyond its budget.
#[test]
fn a_refine_dispatches_only_what_its_budget_can_finish() {
    let (actors, node, _, mut sessions) = setup();
    let increment = actors.method(COUNTER, "increment");
    let inputs: Vec<Input> = (0..10)
        .map(|_| sessions.request(ALICE, COUNTER, increment, 1u64))
        .collect();
    let mut counts = Vec::new();
    for budget in (0..60).map(|step| defaults::HANDLER_GAS + step * 1_000_000) {
        let work = node.budgeted_work(1, [0; 32], budget, inputs.clone());
        let bytes = node.refine_with(&work, budget);
        assert_eq!(
            node.refine_with(&work, 2 * budget),
            bytes,
            "gas beyond the budget changes nothing"
        );
        let (result, _) = WorkResult::decode(&bytes).unwrap();
        for (index, step) in result.steps.iter().enumerate() {
            assert_eq!(done::<u64>(step), index as u64 + 1);
        }
        counts.push(result.steps.len());
    }
    assert_eq!(counts[0], 0);
    assert!(counts.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(counts.iter().any(|count| 0 < *count && *count < 10));
    assert_eq!(*counts.last().unwrap(), 10);
}

/// A refine given less gas than its batch's budget, beyond what starting
/// and decoding may take, traps at its start rather than run out partway.
#[test]
fn a_refine_given_less_gas_than_its_budget_traps() {
    let (actors, node, _, mut sessions) = setup();
    let increment = actors.method(COUNTER, "increment");
    let budget = 100_000_000;
    let work = node.budgeted_work(
        1,
        [0; 32],
        budget,
        vec![sessions.request(ALICE, COUNTER, increment, 1u64)],
    );
    assert_eq!(node.run_refine(&work, budget).exit, ExitReason::Halt);
    assert_eq!(node.run_refine(&work, budget / 2).exit, ExitReason::Panic);
}

/// A step's first read of an installed record and its served precompiles
/// draw on what its batch's budget leaves above the step's own limit. A
/// step that finds nothing left there waits for the next batch behind a
/// step that ran a handler. With none before it, even behind a sweep and an
/// acknowledgement, it fails, consumed, so nothing waits on it. Every host
/// meters the same.
#[test]
fn a_step_whose_precompiles_overrun_the_budget_waits_or_fails() {
    let (actors, mut node, _, _) = setup();
    let mut jam = Node::jam(true);
    for program in [
        &actors.counter,
        &actors.ledger,
        &actors.checksum,
        &actors.caller,
    ] {
        jam.add(program);
    }
    jam.state = node.state.clone();
    jam.version = node.version;
    let increment = actors.method(COUNTER, "increment");
    let hash = actors.method(COUNTER, "hash");
    // Forty rounds: forty-two compressions, the first round's three blocks
    // and one a round after.
    let hashing = |sequence| {
        request(
            ALICE,
            sequence,
            COUNTER,
            hash,
            (vec![7u8; 300], 40u32).encode(),
        )
    };
    let record = defaults::RECORD_BYTE * node.state[&keys::installed(COUNTER)].len() as u64;
    // A budget that dispatches the hash after `before`, the counter's record
    // read once, with `calls` served precompiles' worth above its limit.
    let budget = |before: u64, calls: u64| {
        before
            + record
            + defaults::STEP_RESERVE
            + 50_000_000
            + defaults::FINISH_RESERVE
            + calls * defaults::PRECOMPILE_SERVING
    };
    let refine = |inputs: &[Input], budget: u64| {
        let work = node.budgeted_work(1, [0; 32], budget, inputs.to_vec());
        let bytes = node.refine_with(&work, budget);
        assert_eq!(
            bytes,
            jam.refine_with(&work, budget),
            "every host meters the same"
        );
        WorkResult::decode(&bytes).unwrap().0
    };

    let incrementing = request(ALICE, 1, COUNTER, increment, 1u64.encode());
    let alone = refine(std::slice::from_ref(&incrementing), OUTER_GAS);
    let incremented = defaults::STEP_RESERVE + ran_done(&alone.steps[0]).gas_used;
    let behind = [incrementing, hashing(2)];
    let waited = refine(&behind, budget(incremented, 10));
    assert_eq!(waited.steps.len(), 1, "the hash waits for the next batch");
    let both = refine(&behind, budget(incremented, 42));
    ran_done(&both.steps[1]);

    let sweep = [
        Input::Sweep { due: Vec::new() },
        Input::Ack {
            to: AgentId(5),
            sequence: 1,
        },
        hashing(1),
    ];
    let short = budget(defaults::SWEEP_RESERVE + defaults::INPUT_RESERVE, 10);
    let result = refine(&sweep, short);
    assert_eq!(
        failed(&result.steps[2]),
        Failure::OutOfGas,
        "behind no handler, it fails"
    );
    node.apply(&node.budgeted_work(1, [0; 32], short, sweep.to_vec()));
    let next = node.batch(2, vec![hashing(2)]);
    ran_done(&next.steps[0]);
}

/// A full batch of small steps takes a small part of a refine's default
/// budget: each its reserve and the gas it used, and its instance's record
/// once.
#[test]
fn a_full_batch_of_small_steps_fits_the_default_budget() {
    let (actors, mut node, _, _) = setup();
    let increment = actors.method(COUNTER, "increment");
    let inputs: Vec<Input> = (1..=256)
        .map(|sequence| request(ALICE, sequence, COUNTER, increment, 1u64.encode()))
        .collect();
    let record = defaults::RECORD_BYTE * node.state[&keys::installed(COUNTER)].len() as u64;
    let work = node.budgeted_work(1, [0; 32], defaults::REFINE_GAS, inputs);
    let result = node.apply(&work);
    assert_eq!(result.steps.len(), 256);
    let taken: u64 = record
        + result
            .steps
            .iter()
            .map(|step| defaults::STEP_RESERVE + ran_done(step).gas_used)
            .sum::<u64>();
    println!(
        "256 increments take {taken} of {}: {} would fit",
        defaults::REFINE_GAS,
        256 * (defaults::REFINE_GAS - defaults::HANDLER_GAS) / taken
    );
    assert!(taken * 5 < defaults::REFINE_GAS, "{taken}");
}

/// An actor's precompile calls cost it their price, as the testkit serves
/// them, though the agent serves each by an exit.
#[test]
fn precompile_calls_cost_their_price() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let hash = actors.method(COUNTER, "hash");
    let arguments = (vec![7u8; 1000], 20u32);
    let result = node.batch(
        1,
        vec![sessions.request(ALICE, COUNTER, hash, arguments.clone())],
    );
    kit.batch(1, [0; 32]);
    let expected = kit.command(ALICE, COUNTER, hash, &arguments.encode());
    let run = ran_done(&result.steps[0]);
    assert_eq!(run.outcome, expected.outcome);
    assert_eq!(run.gas_used, expected.gas_used);
}

/// A workflow method runs in its actor's program, never as a handler: a
/// request naming one starts a workflow, whose first step follows it, a
/// query naming one is unknown, and a call naming one traps.
#[test]
fn a_workflow_method_is_no_handler() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let tally = actors.method(LEDGER, "tally");
    let ops = actors.method(COUNTER, "ops");
    let call = (vec![(6u8, 0u32, 1u32)], (LEDGER.0, tally.0));
    let result = node.batch(
        1,
        vec![
            sessions.request(ALICE, LEDGER, tally, vec![1u64, 2]),
            sessions.request(ALICE, COUNTER, ops, call.clone()),
        ],
    );
    let workflow = WorkflowId(0);
    assert_eq!(ran(&result.steps[0]).outcome, Outcome::Started(workflow));
    let first = ran(&result.steps[1]);
    assert_eq!(first.input, InputRef::Due { workflow });
    assert_eq!(first.outcome, Outcome::Done(vec![]));
    assert_eq!(failed(&result.steps[2]), Failure::Trapped);
    assert_eq!(
        node.query(ALICE, LEDGER, tally, vec![1u64].encode()),
        Outcome::Failed {
            code: Failure::Unknown,
            detail: vec![],
        }
    );
    let record: Workflow = node.value(&keys::workflow(workflow)).unwrap();
    assert_eq!(
        record.state,
        WorkflowState::Ended(Outcome::Done(3u64.encode()))
    );
    kit.batch(1, [0; 32]);
    let started = kit.command(ALICE, LEDGER, tally, &vec![1u64, 2].encode());
    assert_eq!(started.outcome, ran(&result.steps[0]).outcome);
    assert_eq!(started.writes, ran(&result.steps[0]).writes);
    // Due at once, at the batch's time.
    let stepped = kit.due(1, workflow);
    assert_eq!(stepped.writes, first.writes);
    assert_eq!(stepped.gas_used, first.gas_used);
    assert_eq!(stepped.instances, first.instances);
    let trapped = kit.command(ALICE, COUNTER, ops, &call.encode());
    assert_eq!(trapped.outcome, ran(&result.steps[2]).outcome);
    assert_eq!(trapped.gas_used, ran(&result.steps[2]).gas_used);
}

#[test]
fn a_refine_stops_before_its_result_outgrows_the_cap() {
    let (actors, mut node, _, mut sessions) = setup();
    let echo = actors.method(COUNTER, "echo");
    let mut inputs: Vec<Input> = (0..80)
        .map(|_| sessions.request(ALICE, COUNTER, echo, vec![7u8; 64_000]))
        .collect();
    let full = node.batch(1, inputs.clone());
    let ran = full.steps.len();
    assert!(0 < ran && ran < inputs.len(), "{ran} steps");
    assert!(full.encode().len() <= cap::WORK_RESULT);
    let rest = node.batch(2, inputs.split_off(ran));
    assert_eq!(rest.steps.len(), 80 - ran, "the rest run next");
    assert_eq!(done::<Vec<u8>>(&rest.steps[0]), vec![7u8; 64_000]);
}

/// A committed map's writes reach accumulate apart, each a value row with
/// the version that wrote it and a dirty row, with the result's seed kept
/// under that version; reads see the values alone, in the map's order. The
/// testkit keeps the same rows.
#[test]
fn committed_writes_leave_value_dirty_and_seed_rows() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let set = actors.method(COUNTER, "set_entries");
    let entry = actors.method(COUNTER, "entry");
    let entries = actors.method(COUNTER, "entries");
    let batches = [
        vec![(1u64, Some(10u64)), (2, Some(20)), (3, Some(30))],
        vec![(2, None), (3, Some(31)), (4, Some(40))],
        vec![],
    ];
    let mut transform = None;
    for (writes, at) in batches.iter().zip(1u8..) {
        let (time, seed) = (&u64::from(at), &[at; 32]);
        let version = node.version + 1;
        let input = sessions.request(ALICE, COUNTER, set, writes.clone());
        let result = node.apply(&node.seeded_work(*time, *seed, vec![input]));
        kit.batch(*time, *seed);
        let step = kit.command(ALICE, COUNTER, set, &writes.encode());
        let run = ran(&result.steps[0]);
        assert!(
            run.writes
                .iter()
                .all(|write| keys::committed_entry(&write.key).is_none())
        );
        assert_eq!(run.committed, step.committed);
        assert_eq!(run.committed.len(), writes.len());
        if let Some(write) = run.committed.first() {
            transform = Some(write.map.transform);
        }
        for write in &run.committed {
            assert!(
                node.state
                    .contains_key(&keys::dirty(version, &write.map, &write.key))
            );
        }
        assert_eq!(
            node.get(&keys::seed(version)),
            (!writes.is_empty()).then(|| seed.to_vec()),
            "a seed only for a version that wrote a committed row"
        );
    }
    // Reads through the map: the values, without their versions.
    let read = |key: u64| node.query(ALICE, COUNTER, entry, key.encode());
    assert_eq!(read(1), Outcome::Done(Some(10u64).encode()));
    assert_eq!(read(2), Outcome::Done(None::<u64>.encode()));
    assert_eq!(read(3), Outcome::Done(Some(31u64).encode()));
    let mut expected = vec![(1u64, 10u64), (3, 31), (4, 40)];
    let transform = transform.expect("the map's transform");
    expected.sort_by_key(|(key, _)| transform.apply(&key.to_be_bytes()));
    let listed = node.query(ALICE, COUNTER, entries, None::<u64>.encode());
    assert_eq!(listed, Outcome::Done(expected.encode()));
    assert_eq!(
        kit.query(ALICE, COUNTER, entries, &None::<u64>.encode()),
        listed
    );
    // The rows themselves, as the testkit keeps them.
    let kept = |key: &Vec<u8>| {
        key.first() == Some(&0x01)
            || key.starts_with(&keys::dirty_prefix())
            || key.starts_with(&keys::seed_prefix())
    };
    let applied: BTreeMap<Vec<u8>, Vec<u8>> = node
        .state
        .iter()
        .filter(|(key, _)| kept(key))
        .map(|(key, value)| (key.clone(), unstored(value).unwrap().to_vec()))
        .collect();
    let reference: BTreeMap<Vec<u8>, Vec<u8>> = kit.rows().into_iter().collect();
    assert_eq!(applied, reference);
    let value_rows = applied
        .keys()
        .filter(|key| keys::committed_entry(key).is_some())
        .count();
    assert_eq!(value_rows, 3, "a deletion removes its value row");
    let dirty_rows = applied
        .keys()
        .filter(|key| keys::dirty_entry(key).is_some())
        .count();
    assert_eq!(dirty_rows, 6, "one per write, deletions included");
}

#[test]
fn state_the_agent_did_not_write_fails_only_the_steps_that_read_it() {
    let (actors, mut node, _, mut sessions) = setup();
    let increment = actors.method(COUNTER, "increment");
    let mint = actors.method(LEDGER, "mint");
    let holders = actors.method(LEDGER, "holders");
    node.batch(
        1,
        vec![
            sessions.request(ALICE, COUNTER, increment, 5u64),
            sessions.request(ALICE, LEDGER, mint, (1u64, 10u64)),
            sessions.request(ALICE, LEDGER, mint, (2u64, 20u64)),
        ],
    );
    let counter = keys::instance_prefix(COUNTER);
    let rows: Vec<Vec<u8>> = node
        .state
        .keys()
        .filter(|key| key.starts_with(&counter))
        .cloned()
        .collect();
    assert!(!rows.is_empty());
    for key in rows {
        node.state.insert(key, vec![0xff]);
    }
    let balances: Vec<Vec<u8>> = node
        .state
        .keys()
        .filter(|key| key.starts_with(&keys::instance_prefix(LEDGER)))
        .cloned()
        .collect();
    node.state.insert(balances.last().unwrap().clone(), vec![]);
    let bob = Sessions::session(&BOB);
    node.state.insert(keys::session_index(&bob), vec![1, 0xff]);

    let result = node.batch(
        2,
        vec![
            sessions.request(ALICE, COUNTER, increment, 1u64),
            sessions.request(ALICE, LEDGER, holders, ()),
            sessions.request(BOB, LEDGER, actors.method(LEDGER, "balance"), 1u64),
            sessions.request(ALICE, LEDGER, actors.method(LEDGER, "balance"), 1u64),
        ],
    );
    assert_eq!(failed(&result.steps[0]), Failure::Trapped, "a corrupt get");
    assert_eq!(failed(&result.steps[1]), Failure::Trapped, "a corrupt scan");
    assert_eq!(
        refused(&result.steps[2]),
        Refusal::Unreadable,
        "a corrupt session index refuses"
    );
    assert_eq!(done::<u64>(&result.steps[3]), 10, "other rows still read");
}

/// One random request among the test actors' handlers.
fn input() -> impl Strategy<Value = (u8, u8, u64, u64)> {
    (0u8..19, 0u8..2, 0u64..200, 0u64..4)
}

/// The request `choice` picks: a handler, its caller, an amount and an
/// account.
fn chosen(actors: &Actors, sessions: &mut Sessions, choice: (u8, u8, u64, u64)) -> Input {
    let (handler, who, amount, account) = choice;
    let caller = if who == 0 { ALICE } else { BOB };
    let m = |instance, name| actors.method(instance, name);
    match handler {
        0 => sessions.request(caller, COUNTER, m(COUNTER, "increment"), amount),
        1 => sessions.request(caller, COUNTER, m(COUNTER, "value"), ()),
        2 => sessions.request(caller, COUNTER, m(COUNTER, "stamp"), ()),
        3 => sessions.request(
            caller,
            COUNTER,
            m(COUNTER, "fill"),
            (amount as u32 % 4, 100u32),
        ),
        4 => sessions.request(caller, COUNTER, m(COUNTER, "spam"), amount as u32 % 3),
        5 => sessions.request(caller, LEDGER, m(LEDGER, "mint"), (account, amount)),
        6 => sessions.request(
            caller,
            LEDGER,
            m(LEDGER, "transfer"),
            ((account, (account + 1) % 4), amount),
        ),
        7 => sessions.request(caller, LEDGER, m(LEDGER, "balance"), account),
        8 => sessions.request(caller, LEDGER, m(LEDGER, "holders"), ()),
        9 => sessions.request(caller, LEDGER, m(LEDGER, "audit"), vec![amount, account]),
        10 => sessions.request(
            caller,
            CALLER,
            m(CALLER, "pay"),
            ((LEDGER.0, account), ((account + 2) % 4, amount)),
        ),
        11 => sessions.request(caller, CALLER, m(CALLER, "relay"), LEDGER.0),
        12 => sessions.request(caller, CALLER, m(CALLER, "ask"), LEDGER.0),
        13 => sessions.request(caller, CALLER, m(CALLER, "recurse"), ()),
        14 => sessions.request(caller, LEDGER, m(LEDGER, "whoami"), ()),
        15 => sessions.request(caller, LEDGER, m(LEDGER, "total"), ()),
        16 => sessions.request(
            caller,
            COUNTER,
            m(COUNTER, "set_entries"),
            vec![(account, Some(amount)), ((account + 1) % 4, None)],
        ),
        17 => sessions.request(caller, COUNTER, m(COUNTER, "entry"), account),
        _ => sessions.request(caller, COUNTER, m(COUNTER, "entries"), Some(account)),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Random batches through the agent agree with the testkit step by
    /// step: outcomes, writes, messages, attests, per-instance gas and
    /// state.
    #[test]
    fn the_agent_matches_the_reference_model(
        batches in prop::collection::vec(prop::collection::vec(input(), 1..6), 1..4),
        seed in any::<[u8; 32]>(),
    ) {
        let (actors, mut node, mut kit, mut sessions) = setup();
        for (number, choices) in batches.into_iter().enumerate() {
            let time = 1 + number as u64;
            let inputs: Vec<Input> = choices
                .into_iter()
                .map(|choice| chosen(&actors, &mut sessions, choice))
                .collect();
            let result = node.apply(&node.seeded_work(time, seed, inputs.clone()));
            kit.batch(time, seed);
            prop_assert_eq!(result.steps.len(), inputs.len());
            for (step, input) in result.steps.iter().zip(&inputs) {
                let Input::Request(request) = input else { unreachable!() };
                let expected = kit.command(request.caller, request.instance, request.method, &request.arguments);
                let run = ran(step);
                prop_assert_eq!(&run.outcome, &expected.outcome);
                prop_assert_eq!(&run.writes, &expected.writes);
                prop_assert_eq!(&run.committed, &expected.committed);
                prop_assert_eq!(&run.messages, &expected.messages);
                prop_assert_eq!(&run.attests, &expected.attests);
                prop_assert_eq!(&run.instances, &expected.instances);
                prop_assert_eq!(run.gas_used, expected.gas_used);
            }
        }
        let applied: BTreeMap<Vec<u8>, Vec<u8>> = node
            .state
            .iter()
            .filter(|(key, _)| {
                key.first() == Some(&0x01)
                    || key.starts_with(&keys::dirty_prefix())
                    || key.starts_with(&keys::seed_prefix())
            })
            .map(|(key, value)| (key.clone(), unstored(value).unwrap().to_vec()))
            .collect();
        let reference: BTreeMap<Vec<u8>, Vec<u8>> = kit.rows().into_iter().collect();
        prop_assert_eq!(applied, reference);
    }
}
