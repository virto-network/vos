//! Packages agree with a VOS node on stateful batches, scans, committed
//! maps and workflows across packages, and refine only on what they show.

use super::*;

/// Stateful batches: installs and roles, requests in new and known
/// sessions, a refused one, messages in and out, an acknowledgement,
/// nested calls, an attestable, precompile calls, and a sweep collecting
/// expired sessions.
#[test]
fn packages_agree_with_vos_on_stateful_batches() {
    for backend in Node::backends() {
        stateful_batches(backend);
    }
}

fn stateful_batches(backend: PvmBackend) {
    let actors = Actors::load();
    let mut paired = Paired::new(backend, &programs(&actors), POLKAJAM_REFINE_GAS);
    let method = |instance, name| actors.method(instance, name);
    let first = installs(&mut paired, &actors);
    ran_or_refused(&paired.batch(T0, first).result);

    let mut inputs = vec![
        paired.request(ALICE, COUNTER, method(COUNTER, "increment"), 5u64),
        paired.request(ALICE, LEDGER, method(LEDGER, "mint"), (1u64, 100u64)),
        paired.request(ALICE, LEDGER, method(LEDGER, "mint"), (2u64, 50u64)),
        paired.request(
            ALICE,
            LEDGER,
            method(LEDGER, "transfer"),
            (1u64, 2u64, 30u64),
        ),
        paired.request(
            BOB,
            COUNTER,
            method(COUNTER, "hash"),
            (vec![7u8; 300], 4u32),
        ),
        paired.request(ALICE, LEDGER, method(LEDGER, "audit"), vec![1u64, 2, 3]),
        paired.request(
            ALICE,
            CALLER,
            method(CALLER, "pay"),
            ((LEDGER.0, 1u64), (2u64, 40u64)),
        ),
        paired.request(BOB, COUNTER, method(COUNTER, "forward"), (5u32, 1u32, 3u64)),
    ];
    let call = Body::Call {
        instance: COUNTER,
        method: method(COUNTER, "increment"),
        arguments: 2u64.encode(),
        awaiting: Some(Await {
            workflow: WorkflowId(4),
            counter: 0,
        }),
    };
    inputs.push(paired.message(AgentId(5), call));
    let second = paired.batch(T0 + 1_000, inputs);
    ran_or_refused(&second.result);
    assert!(second.jam_gas > second.simulated_gas);

    // A duplicate, refused; Bob's next; an acknowledgement of the forward.
    let duplicate = Input::Request(Request {
        sequence: 1,
        ..match paired.request(ALICE, COUNTER, method(COUNTER, "value"), ()) {
            Input::Request(request) => request,
            _ => unreachable!(),
        }
    });
    let inputs = vec![
        duplicate,
        paired.request(BOB, COUNTER, method(COUNTER, "increment"), 1u64),
        Input::Ack {
            to: AgentId(5),
            sequence: 2,
        },
    ];
    let third = paired.batch(T0 + 2_000, inputs);
    assert!(matches!(third.result.steps[0], Step::Refused { .. }));

    // Two hours on, every session has expired: the sweep collects them.
    let later = T0 + 2 * 60 * 60 * 1000;
    let sweep = paired.vos.sweep(later);
    let Input::Sweep { due } = &sweep else {
        unreachable!()
    };
    assert!(!due.is_empty(), "sessions due");
    let swept = paired.batch(later, vec![sweep]);
    assert!(matches!(&swept.result.steps[0], Step::Swept { due } if !due.is_empty()));
    let alices = Session {
        key: [1; 32],
        name: [0; 16],
        t0: T0,
    };
    assert_eq!(paired.vos.session(&alices), None, "collected");
}

/// Scans of both table transforms, from cursors and across refills, a
/// scan whose first row alone fills its page, and committed maps written,
/// deleted and iterated.
#[test]
fn packages_agree_with_vos_on_scans_and_committed_maps() {
    for backend in Node::backends() {
        scans_and_committed_maps(backend);
    }
}

fn scans_and_committed_maps(backend: PvmBackend) {
    let actors = Actors::load();
    let mut paired = Paired::new(backend, &programs(&actors), POLKAJAM_REFINE_GAS);
    let method = |instance, name| actors.method(instance, name);
    let first = installs(&mut paired, &actors);
    paired.batch(T0, first);

    // Raw tables of both transforms, from every cursor.
    let scan = method(COUNTER, "put_and_scan");
    let keys = vec![
        vec![4u8, 1],
        vec![4, 2],
        vec![5, 1],
        vec![],
        vec![4, 0],
        vec![0, 0],
    ];
    let mut inputs = Vec::new();
    for transform in [Transform::Hashed, Transform::Ordered] {
        let rows = Rows::Table { tag: 7, transform }.register();
        let cursors = [None, Some(vec![4u8, 9]), Some(vec![6])]
            .into_iter()
            .chain(keys.iter().cloned().map(Some));
        for cursor in cursors {
            inputs.push(paired.request(ALICE, COUNTER, scan, (rows, keys.clone(), cursor)));
        }
    }
    ran_or_refused(&paired.batch(T0 + 1_000, inputs).result);

    // A hashed table, a committed map and an ordered table, filled, each
    // step within JAM's rows a step writes, and each iterated across more
    // than a scan's page.
    let count = 300u64;
    let entries: Vec<(u64, Option<u64>)> = (0..count).map(|key| (key * 7, Some(key))).collect();
    let accounts: Vec<(u64, u64)> = (0..count).map(|id| (id * 11, id + 1)).collect();
    let mut inputs = vec![paired.request(
        ALICE,
        COUNTER,
        method(COUNTER, "fill"),
        (cap::JAM.step_rows as u32 - 8, 8u32),
    )];
    for chunk in entries.chunks(100) {
        let set = method(COUNTER, "set_entries");
        inputs.push(paired.request(ALICE, COUNTER, set, chunk.to_vec()));
    }
    for chunk in accounts.chunks(100) {
        let mint = method(LEDGER, "mint_all");
        inputs.push(paired.request(ALICE, LEDGER, mint, chunk.to_vec()));
    }
    ran_or_refused(&paired.batch(T0 + 2_000, inputs).result);

    // Each iterated across its scan's refills; some entries deleted, and
    // the map iterated again in the same batch.
    let deleted: Vec<(u64, Option<u64>)> = (0..count / 3).map(|key| (key * 21, None)).collect();
    let inputs = vec![
        paired.request(ALICE, COUNTER, method(COUNTER, "blob_keys"), ()),
        paired.request(ALICE, COUNTER, method(COUNTER, "entries"), None::<u64>),
        paired.request(ALICE, LEDGER, method(LEDGER, "holders"), ()),
        paired.request(ALICE, COUNTER, method(COUNTER, "set_entries"), deleted),
        paired.request(ALICE, COUNTER, method(COUNTER, "entries"), Some(70u64)),
    ];
    ran_or_refused(&paired.batch(T0 + 3_000, inputs).result);

    // Rows larger than a scan's first page: the agent asks again with room
    // for the largest row.
    let rows = Rows::Table {
        tag: 8,
        transform: Transform::Ordered,
    }
    .register();
    let store = method(COUNTER, "store");
    let mut inputs: Vec<Input> = (0..3u8)
        .map(|key| paired.request(ALICE, COUNTER, store, (rows, vec![key], 6_000u32)))
        .collect();
    inputs.push(paired.request(
        ALICE,
        COUNTER,
        method(COUNTER, "scan_rows"),
        (rows, None::<Vec<u8>>, 20_000u32),
    ));
    ran_or_refused(&paired.batch(T0 + 4_000, inputs).result);
    let inputs = vec![paired.request(
        ALICE,
        COUNTER,
        method(COUNTER, "scan_rows"),
        (rows, Some(vec![0u8]), 20_000u32),
    )];
    ran_or_refused(&paired.batch(T0 + 5_000, inputs).result);
}

/// The shop's workflows, suspended in one package and resumed in later
/// ones: awaiting another agent's replies, sleeping until a sweep resumes
/// them, computing over pages written, and putting pages back to their
/// base. Each resumed step imports its pages from the packages that
/// exported them.
#[test]
fn packages_agree_with_vos_on_workflows_across_packages() {
    for backend in Node::backends() {
        workflows_across_packages(backend);
    }
}

fn workflows_across_packages(backend: PvmBackend) {
    let actors = Actors::load();
    let (mut paired, shop) = with_shop(backend, &actors);

    let start = |paired: &mut Paired, name: &str, arguments: Vec<u8>| {
        let method = method(&shop, name);
        let sequence = paired.sequences.entry(ALICE).or_insert(0);
        *sequence += 1;
        Input::Request(Request {
            session: Session {
                key: [1; 32],
                name: [0; 16],
                t0: T0,
            },
            sequence: *sequence,
            caller: ALICE,
            instance: SHOP,
            method,
            arguments,
        })
    };
    let starts = vec![
        start(&mut paired, "saga", (RISK.0, 3u32).encode()),
        start(&mut paired, "compute", (20_000u32, 3u32).encode()),
        start(&mut paired, "scratch", RISK.0.encode()),
        start(&mut paired, "nap", 2_500u64.encode()),
        start(&mut paired, "record", (7u64, 30u64).encode()),
        start(&mut paired, "restock", vec![5u64, 6, 7].encode()),
    ];
    let mut ran = paired.batch(T0 + 1_000, starts);
    let (mut imported, mut exported) = (ran.imported, ran.exported);
    let beyond = |ran: &Ran| ran.jam_gas as i64 - ran.simulated_gas as i64;
    let mut overhead = beyond(&ran);
    let mut time = T0 + 1_000;
    let mut answered = 0u64;
    for _ in 0..40 {
        // Each request to the risk agent answered, the sweep's due steps
        // run, and what the risk agent got acknowledged.
        time += 1_000;
        let mut inputs = Vec::new();
        let sweep = paired.vos.sweep(time);
        if matches!(&sweep, Input::Sweep { due } if !due.is_empty()) {
            inputs.push(sweep);
        }
        for awaiting in requests(&ran.result) {
            answered += 1;
            let reply = Body::Reply {
                awaiting,
                answer: Answer::Done(answered.encode()),
            };
            inputs.push(paired.message(RISK, reply));
        }
        if inputs.is_empty() {
            break;
        }
        ran = paired.batch(time, inputs);
        imported += ran.imported;
        exported += ran.exported;
        overhead = overhead.max(beyond(&ran));
    }
    for id in 0..6 {
        assert!(
            matches!(paired.record(id).state, WorkflowState::Ended(_)),
            "workflow {id} ended"
        );
    }
    // Sections' rows, witnessed: what each section read and wrote.
    assert_eq!(
        paired.record(4).state,
        WorkflowState::Ended(Outcome::Done((30u64, Some(30u64)).encode()))
    );
    let WorkflowState::Ended(Outcome::Done(restocked)) = paired.record(5).state else {
        panic!("restocked");
    };
    let restocked: Vec<u64> = vos_testkit::decode(&restocked).unwrap();
    assert_eq!(restocked.len(), 3);
    assert!(restocked.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        answered >= 5,
        "the saga's and the scratch's awaits answered"
    );
    assert!(
        exported > 0 && imported > 0,
        "pages exported, then imported"
    );
    println!(
        "JAM: pages exported {exported}, imported {imported}; a package's refine at most \
         {overhead} gas beyond the simulation's"
    );
}

/// The awaits of the requests to the risk agent a result sends.
fn requests(result: &WorkResult) -> Vec<Await> {
    result
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Ran(run) => Some(&run.messages),
            _ => None,
        })
        .flatten()
        .filter_map(|message| match message {
            Outgoing {
                to,
                body:
                    Body::Call {
                        awaiting: Some(awaiting),
                        ..
                    },
            } if *to == RISK => Some(*awaiting),
            _ => None,
        })
        .collect()
}

/// A witnessed read's gas on JAM, beyond the VOS refine's: per key the
/// witness opens, and per scan, by the rows of its range. Rows of a hashed
/// table of 1,000; a scan reads a page of applied rows at a time, some 90
/// of these, however few its actor asks for.
#[test]
fn a_witnessed_reads_gas_on_jam() {
    let actors = Actors::load();
    let mut paired = Paired::new(PvmBackend::Default, &programs(&actors), POLKAJAM_REFINE_GAS);
    let first = installs(&mut paired, &actors);
    paired.batch(T0, first);
    let ops = actors.method(COUNTER, "ops");
    let phases = |phases: Vec<(u8, u32, u32)>| (phases, COUNTER.0, ops.0);
    // A thousand rows, in steps within JAM's rows a step writes.
    let fills = (0..8)
        .map(|step| paired.request(ALICE, COUNTER, ops, phases(vec![(3, step * 125, 125)])))
        .collect();
    ran_or_refused(&paired.batch(T0 + 1_000, fills).result);
    let mut time = T0 + 1_000;
    // A request's package: its JAM refine's gas beyond the simulation's,
    // the keys its witness opens and the rows its ranges hold.
    let mut run = |paired: &mut Paired, request: Input| {
        time += 1_000;
        let ran = paired.batch(time, vec![request]);
        ran_or_refused(&ran.result);
        let extra = ran.jam_gas as i64 - ran.simulated_gas as i64;
        (extra, ran.witnessed as i64, ran.scanned as i64)
    };
    let none = paired.request(ALICE, COUNTER, ops, phases(vec![(2, 0, 0)]));
    let (base, base_keys, _) = run(&mut paired, none);
    let get = paired.request(ALICE, COUNTER, ops, phases(vec![(2, 500, 1)]));
    let (lone, _, _) = run(&mut paired, get);
    let gets = paired.request(ALICE, COUNTER, ops, phases(vec![(2, 0, 64)]));
    let (read, keys, _) = run(&mut paired, gets);
    let per_key = (read - base) / (keys - base_keys);
    println!(
        "JAM: a witnessed read alone, {} gas beyond a VOS read; among 64, {per_key} a key",
        lone - base
    );
    let scan = actors.method(COUNTER, "scan_rows");
    let raw = Rows::Table {
        tag: 3,
        transform: Transform::Hashed,
    }
    .register();
    // Rows of 4 bytes of key and 1 of value: 13 bytes each, framed.
    for wanted in [8u32, 1_000] {
        let request = paired.request(ALICE, COUNTER, scan, (raw, None::<Vec<u8>>, 13 * wanted));
        let (extra, _, rows) = run(&mut paired, request);
        let scanned = extra - base;
        println!(
            "JAM: a scan of {wanted} rows reads a range of {rows}: {scanned} gas beyond a VOS \
             scan, {} a row",
            scanned / rows
        );
        assert!(scanned > 0);
    }
    assert!(per_key > 0);
}

/// A package refines only on what its witness shows: a read it does not
/// cover, a value that is not the row's, a scan past its ranges and an
/// import that is not the page each trap its refine. Accumulate takes
/// only a root after the one it holds, at a time that fits its slot.
#[test]
fn a_package_refines_and_accumulates_only_on_what_it_shows() {
    let actors = Actors::load();
    let (mut paired, shop) = with_shop(PvmBackend::Default, &actors);
    let fill = paired.request(
        ALICE,
        COUNTER,
        actors.method(COUNTER, "fill"),
        (40u32, 8u32),
    );
    let compute = paired.request(ALICE, SHOP, method(&shop, "compute"), (20_000u32, 2u32));
    paired.batch(T0 + 1_000, vec![fill, compute]);

    let refines = |paired: &mut Paired, package: &Package, imports| {
        paired.chain.refine(
            &paired.runner,
            &Work::encode_package(package),
            imports,
            POLKAJAM_REFINE_GAS,
        )
    };
    let prepare = |paired: &Paired, inputs: Vec<Input>, time: u64| {
        let segments = paired.chain.segments();
        paired
            .builder
            .prepare(&paired.runner, segments, inputs, time, [3; 32], &[])
            .expect("a package")
    };
    let trapped = |refined: Result<Refined, Error>, what: &str| {
        assert!(
            matches!(refined, Err(Error::Refine(vos_pvm::ExitReason::Panic))),
            "{what}: {refined:?}"
        );
    };

    // A read left out of the witness, a value not the row's, a row read
    // but opened by its commitment alone, and keys out of order.
    let read = paired.request(ALICE, COUNTER, actors.method(COUNTER, "value"), ());
    let prepared = prepare(&paired, vec![read], T0 + 2_000);
    let at = prepared
        .package
        .witness
        .keys
        .iter()
        .position(|(_, opened)| matches!(opened, Opened::Value { .. }))
        .expect("a row read");
    let altered = |alter: &dyn Fn(&mut WitnessKeys)| {
        let mut package = prepared.package.clone();
        alter(&mut package.witness.keys);
        package
    };
    let left_out = altered(&|keys| {
        keys.remove(at);
    });
    let tampered = altered(&|keys| {
        if let Opened::Value { value, .. } = &mut keys[at].1 {
            value.push(0);
        }
    });
    let hidden = altered(&|keys| {
        if let Opened::Value { salt, value } = &keys[at].1 {
            keys[at].1 = Opened::Written(vos_tree::value_hash(&Blake2b, salt, value));
        }
    });
    let unsorted = altered(&|keys| keys.swap(0, 1));
    for (package, what, verifies) in [
        (left_out, "a read not covered", true),
        (tampered, "a value not the row's", false),
        (hidden, "a read of a row opened written", true),
        (unsorted, "keys out of order", true),
    ] {
        assert_eq!(shows(&package), verifies, "{what}");
        trapped(refines(&mut paired, &package, vec![]), what);
    }

    // A scan's range cut short, with a proof of what it still holds, and
    // ranges that overlap. The read never applied, the scan takes its
    // place in Alice's session.
    *paired.sequences.get_mut(&ALICE).unwrap() -= 1;
    let scan = paired.request(ALICE, COUNTER, actors.method(COUNTER, "blob_keys"), ());
    let prepared = prepare(&paired, vec![scan], T0 + 2_000);
    let mut package = prepared.package.clone();
    let widest = |package: &mut Package| {
        let ranges = package.witness.ranges.iter_mut();
        ranges
            .max_by_key(|range| range.rows.len())
            .expect("a scanned range")
            .clone()
    };
    let mut cut = widest(&mut package);
    let to = vos_tree::keys::after(&cut.rows[0].key);
    cut.rows.truncate(1);
    let view = paired.builder.store.view();
    cut.proof = vos_tree::RangeProof::generate(&view.tree(), &cut.from, Some(&to)).unwrap();
    cut.to = Some(to);
    let whole = widest(&mut package);
    package.witness.ranges = vec![cut];
    assert!(shows(&package), "the range cut short verifies");
    trapped(
        refines(&mut paired, &package, vec![]),
        "a scan past its range",
    );
    package.witness.ranges = vec![whole.clone(), whole];
    assert!(shows(&package), "each range verifies");
    trapped(
        refines(&mut paired, &package, vec![]),
        "ranges that overlap",
    );

    // The computation's pages: missing from DA, then imported as zeros.
    let time = T0 + 3_000;
    let sweep = paired.vos.sweep(time);
    // A workflow whose pages DA lacks is left out of the sweep, and stays
    // due.
    let empty = vos_jam::Da::default();
    let missing = paired
        .builder
        .prepare(
            &paired.runner,
            Arc::new(empty.clone()),
            vec![sweep.clone()],
            time,
            [3; 32],
            &[],
        )
        .expect("a package without it");
    assert_eq!(missing.skipped, [WorkflowId(0)]);
    assert!(missing.package.batch.inputs.is_empty());
    let prepared = prepare(&paired, vec![sweep], time);
    assert!(matches!(
        prepared.imports(&empty),
        Err(Error::Page(WorkflowId(0), _))
    ));
    assert!(!prepared.segments.is_empty(), "the computation's pages");
    let zeros = vec![vec![0u8; vos_wire::package::SEGMENT]; prepared.segments.len()];
    trapped(
        refines(&mut paired, &prepared.package, zeros),
        "an import not the page",
    );

    // The package as built refines. Accumulated where its time is too
    // early for the slot, or too late, the chain keeps its root, and the
    // builder its store.
    let imports = prepared.imports(&paired.chain.da).expect("the pages in DA");
    let refined = refines(&mut paired, &prepared.package, imports).expect("it refines");
    let before = (paired.chain.root(), paired.builder.store.root().unwrap());
    let skew = defaults::SESSION_SKEW_MS;
    let late = slot_of(time + skew) + 2;
    let early = slot_of(time - skew) - 2;
    for (slot, what) in [
        (late, "a time too early for its slot"),
        (early, "a time ahead of its slot"),
    ] {
        let stored = paired
            .chain
            .accumulate(&paired.runner, &refined, slot)
            .unwrap();
        assert_eq!(stored, before.0, "{what}");
        let landed = paired.chain.landed().unwrap();
        let accepted = paired.builder.accept(&prepared, &landed, &paired.chain.da);
        assert_eq!(accepted, Err(Error::Unaccumulated), "{what}");
        assert_eq!(paired.builder.store.root().unwrap(), before.1, "{what}");
    }
    // Accumulated in its slot, then taken, its pages where it exported
    // them.
    let slot = slot_of(time);
    let stored = paired
        .chain
        .accumulate(&paired.runner, &refined, slot)
        .unwrap();
    assert_eq!(stored, Some(refined.output.root_after));
    let landed = paired.chain.landed().unwrap();
    let exports = landed.exports.unwrap();
    let wrong = Landed {
        exports: Some(vos_wire::package::Exports {
            pages: exports.pages + 1,
            ..exports
        }),
        ..landed
    };
    assert_eq!(
        paired.builder.accept(&prepared, &wrong, &paired.chain.da),
        Err(Error::Exports),
        "exports that are not its pages"
    );
    assert_eq!(paired.builder.store.root().unwrap(), before.1);
    assert!(
        paired
            .builder
            .accept(&prepared, &landed, &paired.chain.da)
            .is_ok()
    );
    // Once more: built on a root neither holds now.
    let again = paired
        .chain
        .accumulate(&paired.runner, &refined, slot)
        .unwrap();
    assert_eq!(again, stored, "the chain keeps the root after");
    assert_eq!(
        paired.builder.accept(&prepared, &landed, &paired.chain.da),
        Err(Error::Root)
    );
}
