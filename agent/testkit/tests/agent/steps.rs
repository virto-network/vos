//! A batch's steps: what each runs and writes, the caps it holds, the
//! calls it nests, the state it reads, how much of a batch a refine takes
//! on, and the testkit's answer for each.

use std::collections::BTreeMap;

use proptest::prelude::*;
use vos_testkit::programs::{method, table_tag};
use vos_testkit::{Testkit, decode};
use vos_wire::abi::{Failure, Refusal, Rows, cap, code};
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::unstored;
use vos_wire::result::{Outcome, WorkResult};
use vos_wire::{Decode, Encode};

use crate::common::{
    AGENT, ALICE, Actors, BOB, CALLER, COUNTER, LEDGER, MINTER, Node, Sessions, done, failed,
    install, ran, refused, setup,
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
fn an_attestable_may_not_write_its_arguments() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    // store_ind_u8 [φ7] = φ0, then return to the halt address.
    let scribble = build_standard_program(&StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code: vec![120, 0x70, 50, 0],
            bitmask: vec![1, 0, 1, 0],
        },
    })
    .unwrap();
    let actors = Actors::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    let ledger = node.add(&actors.ledger);
    let program = node.add(&scribble);
    let checksum = method(&actors.ledger, "checksum");
    node.batch(
        0,
        vec![Input::Admin(Admin::Install {
            instance: LEDGER,
            program: ledger,
            attestables: vec![(checksum, program)],
            roles: vec![(b"minter".to_vec(), MINTER)],
        })],
    );
    kit.install(
        LEDGER,
        &actors.ledger,
        &[(checksum, &scribble)],
        &[("minter", MINTER)],
    )
    .unwrap();
    let audit = actors.method(LEDGER, "audit");
    let mut sessions = Sessions::new();
    let result = node.batch(1, vec![sessions.request(ALICE, LEDGER, audit, vec![1u64])]);
    assert_eq!(failed(&result.steps[0]), Failure::Trapped);
    kit.batch(1, [0; 32]);
    let expected = kit.command(ALICE, LEDGER, audit, &vec![1u64].encode());
    assert_eq!(ran(&result.steps[0]).outcome, expected.outcome);
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

#[test]
fn a_refine_dispatches_only_what_its_gas_can_finish() {
    let (actors, node, _, mut sessions) = setup();
    let increment = actors.method(COUNTER, "increment");
    let work = node.work(
        1,
        (0..10)
            .map(|_| sessions.request(ALICE, COUNTER, increment, 1u64))
            .collect(),
    );
    // From less than a handler's limit up: every refine halts with a prefix
    // of the batch, longer as the gas grows.
    let mut counts = Vec::new();
    for gas in (0..60).map(|step| vos_wire::defaults::HANDLER_GAS + step * 100_000) {
        let (result, _) = WorkResult::decode(&node.refine_with(&work, gas)).unwrap();
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

/// A table's scan returns its raw keys in the table's order, hash order or
/// key order, from any cursor, the step's own writes and the batch's
/// earlier ones included; the testkit agrees.
#[test]
fn a_scan_runs_in_its_tables_order_from_any_cursor() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let scan = actors.method(COUNTER, "put_and_scan");
    let keys = vec![
        vec![4u8, 1],
        vec![4, 2],
        vec![5, 1],
        vec![],
        vec![4, 0],
        vec![0, 0],
    ];
    let row = |key: &[u8]| (key.to_vec(), vec![1u8]).encode();
    let mut cases = Vec::new();
    for transform in [Transform::Hashed, Transform::Ordered] {
        let rows = Rows::Table { tag: 7, transform }.register();
        let mut ordered = keys.clone();
        ordered.sort_by_key(|key| transform.apply(key));
        if transform == Transform::Ordered {
            assert_eq!(ordered, {
                let mut sorted = keys.clone();
                sorted.sort();
                sorted
            });
        }
        let cursors = [None, Some(vec![4u8, 9]), Some(vec![6])]
            .into_iter()
            .chain(keys.iter().cloned().map(Some));
        for cursor in cursors {
            let expected: Vec<u8> = ordered
                .iter()
                .filter(|key| {
                    cursor
                        .as_ref()
                        .is_none_or(|cursor| transform.apply(key) > transform.apply(cursor))
                })
                .flat_map(|key| row(key))
                .collect();
            cases.push(((rows, keys.clone(), cursor), expected));
        }
    }
    let inputs = cases
        .iter()
        .map(|(arguments, _)| sessions.request(ALICE, COUNTER, scan, arguments.clone()))
        .collect();
    let result = node.batch(1, inputs);
    kit.batch(1, [0; 32]);
    for ((arguments, expected), step) in cases.iter().zip(&result.steps) {
        assert_eq!(&done::<Vec<u8>>(step), expected, "{arguments:?}");
        let reference = kit.command(ALICE, COUNTER, scan, &arguments.encode());
        assert_eq!(
            reference.outcome,
            ran(step).outcome,
            "testkit, {arguments:?}"
        );
    }
}

/// An ordered table's key, as a row's or a scan's cursor, holds
/// `cap::ORDERED_KEY` bytes; one byte past fails the step, where a hashed
/// table takes it. The testkit agrees.
#[test]
fn an_ordered_key_past_its_cap_fails_the_step() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let scan = actors.method(COUNTER, "put_and_scan");
    let rows = |transform| Rows::Table { tag: 7, transform }.register();
    let long = vec![9u8; cap::ORDERED_KEY + 1];
    let cases = [
        (
            (rows(Transform::Ordered), vec![long[1..].to_vec()], None),
            None,
        ),
        (
            (rows(Transform::Ordered), vec![long.clone()], None),
            Some(Failure::Cap),
        ),
        (
            (rows(Transform::Ordered), vec![], Some(long.clone())),
            Some(Failure::Cap),
        ),
        (
            (
                rows(Transform::Hashed),
                vec![long.clone()],
                Some(long.clone()),
            ),
            None,
        ),
    ];
    let inputs = cases
        .iter()
        .map(|(arguments, _)| sessions.request(ALICE, COUNTER, scan, arguments.clone()))
        .collect();
    let result = node.batch(1, inputs);
    kit.batch(1, [0; 32]);
    for ((arguments, expected), step) in cases.iter().zip(&result.steps) {
        match expected {
            Some(code) => assert_eq!(failed(step), *code),
            None => assert!(matches!(ran(step).outcome, Outcome::Done(_))),
        }
        let reference = kit.command(ALICE, COUNTER, scan, &arguments.encode());
        assert_eq!(reference.outcome, ran(step).outcome);
        assert_eq!(reference.gas_used, ran(step).gas_used);
    }
}

/// Rows at both caps (a key of zero bytes, which doubles escaped, and the
/// largest value) in a hashed table, a committed map, and an ordered table
/// at its own key cap, scan back whole in a later batch; an output too
/// small for one is `FULL`. The testkit agrees.
#[test]
fn rows_at_their_caps_scan_back_in_a_later_batch() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let store = actors.method(COUNTER, "store");
    let scan = actors.method(COUNTER, "scan_rows");
    let tables = [
        (
            Rows::Table {
                tag: 9,
                transform: Transform::Hashed,
            },
            cap::KEY,
        ),
        (
            Rows::Committed {
                tag: 9,
                transform: Transform::Hashed,
            },
            cap::KEY,
        ),
        (
            Rows::Table {
                tag: 9,
                transform: Transform::Ordered,
            },
            cap::ORDERED_KEY,
        ),
    ];
    let stores: Vec<_> = tables
        .iter()
        .map(|(rows, key)| (rows.register(), vec![0u8; *key], cap::VALUE as u32))
        .collect();
    let scans: Vec<_> = tables
        .iter()
        .flat_map(|(rows, _)| {
            [cap::SCAN as u32, 1024].map(|capacity| (rows.register(), None::<Vec<u8>>, capacity))
        })
        .collect();
    let first = node.batch(
        1,
        stores
            .iter()
            .map(|arguments| sessions.request(ALICE, COUNTER, store, arguments.clone()))
            .collect(),
    );
    kit.batch(1, [0; 32]);
    for (arguments, step) in stores.iter().zip(&first.steps) {
        assert_eq!(done::<u32>(step), cap::VALUE as u32);
        let reference = kit.command(ALICE, COUNTER, store, &arguments.encode());
        assert_eq!(reference.outcome, ran(step).outcome);
    }
    let second = node.batch(
        2,
        scans
            .iter()
            .map(|arguments| sessions.request(ALICE, COUNTER, scan, arguments.clone()))
            .collect(),
    );
    kit.batch(2, [0; 32]);
    for ((arguments, step), (_, key)) in scans
        .iter()
        .zip(&second.steps)
        .zip(tables.iter().flat_map(|table| [table, table]))
    {
        let (written, rows) = done::<(u64, Vec<(Vec<u8>, u32, u64)>)>(step);
        if arguments.2 == 1024 {
            assert_eq!((written, rows.len()), (code::FULL, 0), "{arguments:?}");
        } else {
            let row = (vec![0u8; *key], cap::VALUE as u32, 7 * cap::VALUE as u64);
            assert_eq!(rows, vec![row], "{arguments:?}");
            assert_eq!(written as usize, 8 + key + cap::VALUE);
        }
        let reference = kit.command(ALICE, COUNTER, scan, &arguments.encode());
        assert_eq!(
            reference.outcome,
            ran(step).outcome,
            "testkit, {arguments:?}"
        );
        assert_eq!(
            reference.gas_used,
            ran(step).gas_used,
            "testkit, {arguments:?}"
        );
    }
}

/// Tables and committed maps iterate across the buffer refills of a scan,
/// in their order: a hashed table in hash order, an ordered one in key
/// order, a committed map in its own. The testkit agrees.
#[test]
fn rows_iterate_in_order_across_refills() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let count = 300u64;
    let entries: Vec<(u64, Option<u64>)> = (0..count).map(|key| (key * 7, Some(key))).collect();
    let accounts: Vec<(u64, u64)> = (0..count).map(|id| (id * 11, id + 1)).collect();
    let writes = [
        (
            COUNTER,
            actors.method(COUNTER, "fill"),
            (count as u32, 8u32).encode(),
        ),
        (
            COUNTER,
            actors.method(COUNTER, "set_entries"),
            entries.encode(),
        ),
        (LEDGER, actors.method(LEDGER, "mint_all"), accounts.encode()),
    ];
    let reads = [
        (COUNTER, actors.method(COUNTER, "blob_keys"), ().encode()),
        (
            COUNTER,
            actors.method(COUNTER, "entries"),
            None::<u64>.encode(),
        ),
        (LEDGER, actors.method(LEDGER, "holders"), ().encode()),
    ];
    let request =
        |sessions: &mut Sessions,
         (instance, method, arguments): &(InstanceId, MethodId, Vec<u8>)| {
            sessions.request_bytes(ALICE, *instance, *method, arguments.clone())
        };
    let first = node.batch(
        1,
        writes
            .iter()
            .map(|call| request(&mut sessions, call))
            .collect(),
    );
    kit.batch(1, [0; 32]);
    for ((instance, method, arguments), step) in writes.iter().zip(&first.steps) {
        let reference = kit.command(ALICE, *instance, *method, arguments);
        assert_eq!(reference.outcome, ran(step).outcome);
        assert!(matches!(ran(step).outcome, Outcome::Done(_)));
    }
    let second = node.batch(
        2,
        reads
            .iter()
            .map(|call| request(&mut sessions, call))
            .collect(),
    );
    kit.batch(2, [0; 32]);
    for ((instance, method, arguments), step) in reads.iter().zip(&second.steps) {
        let reference = kit.command(ALICE, *instance, *method, arguments);
        assert_eq!(reference.outcome, ran(step).outcome);
    }
    // Each in its table's order, as the rows' keys carry the transform.
    let transform_of = |prefix: Vec<u8>| {
        let key = node
            .state
            .keys()
            .find(|key| key.starts_with(&prefix))
            .expect("a row of the table");
        Transform::from_tag(key[prefix.len()]).expect("a transform")
    };
    let blobs = transform_of(keys::table_prefix(COUNTER, table_tag("blobs")));
    let mut expected: Vec<u32> = (0..count as u32).collect();
    expected.sort_by_key(|key| blobs.apply(&key.to_be_bytes()));
    assert_eq!(done::<Vec<u32>>(&second.steps[0]), expected);
    let map = ran(&first.steps[1]).committed[0].map;
    let mut expected: Vec<(u64, u64)> = (0..count).map(|key| (key * 7, key)).collect();
    expected.sort_by_key(|(key, _)| map.transform.apply(&key.to_be_bytes()));
    assert_eq!(done::<Vec<(u64, u64)>>(&second.steps[1]), expected);
    assert_eq!(
        done::<Vec<(u64, u64)>>(&second.steps[2]),
        accounts,
        "key order"
    );
}

/// A register no rows answer to, a struct key that is not empty, or a scan
/// of the struct fails the invocation; the testkit agrees.
#[test]
fn rows_the_agent_does_not_know_fail_the_invocation() {
    let (actors, mut node, mut kit, mut sessions) = setup();
    let scan = actors.method(COUNTER, "put_and_scan");
    let table = Rows::Table {
        tag: 7,
        transform: Transform::Hashed,
    }
    .register();
    let cases = [
        (Rows::Struct.register(), vec![vec![1u8]], "a struct key"),
        (Rows::Struct.register(), vec![], "a scan of the struct"),
        (3 << 40, vec![vec![1]], "a fourth kind"),
        (table | 2 << 32, vec![vec![1]], "a third transform"),
        (table | 1 << 48, vec![vec![1]], "bits past the kind"),
        (1, vec![vec![1]], "a struct with a tag"),
    ];
    let inputs = cases
        .iter()
        .map(|(rows, keys, _)| {
            sessions.request(ALICE, COUNTER, scan, (*rows, keys.clone(), None::<Vec<u8>>))
        })
        .collect();
    let result = node.batch(1, inputs);
    kit.batch(1, [0; 32]);
    for ((rows, keys, what), step) in cases.iter().zip(&result.steps) {
        assert_eq!(failed(step), Failure::Trapped, "{what}");
        let arguments = (*rows, keys.clone(), None::<Vec<u8>>).encode();
        let reference = kit.command(ALICE, COUNTER, scan, &arguments);
        assert_eq!(reference.outcome, ran(step).outcome, "testkit, {what}");
        assert_eq!(reference.gas_used, ran(step).gas_used, "testkit, {what}");
    }
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
