//! Scans: a table's rows in its order, from any cursor, through refills
//! and at their caps; and rows the agent does not know.

use super::*;

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
