//! A read served and stated; what the kernel traps on, what the agent does
//! not serve and refuses at the ask, a read not served in time; the public
//! arguments' order; and an at-cut attest's count against a step's.

use super::*;

/// A workflow asks to read entries at the cut of its window: its step
/// records the request, the rows by their full keys in order, and pauses
/// awaiting it until `B_{w+3}`. Served, the kernel runs on the call's
/// arguments and the rows, the absent one proved absent, and its statement
/// is recorded: the window, the witness input the arguments then the
/// served rows, the reader and the `#[public]` keys as its public
/// arguments, and the space root `S_w` over the representative's root. The
/// workflow ends with the sum, the request gone.
#[test]
fn a_read_at_a_cut_is_served_and_stated() {
    let mut reads = Reads::with(&[(1, 10), (2, 20), (5, 7)]);
    let keys = vec![1u64, 2, 9];
    let id = reads.start(T0 + 10, "sum_at_cut", keys.clone());
    let record = reads.record(id);
    let deadline = CLOCK.boundary(WINDOW + defaults::READ_WINDOWS).unwrap();
    assert!(
        matches!(
            record.state,
            WorkflowState::Attesting { counter: 0, window: WINDOW, deadline: at, .. } if at == deadline
        ),
        "{:?}",
        record.state
    );
    assert_eq!(record.due, deadline);
    let (request, read) = reads.asked(WINDOW, id, 0);
    assert_eq!(
        read,
        PendingRead {
            instance: READER,
            rows: entry_rows(&keys),
        }
    );
    let served = reads.served(WINDOW, &read);
    assert_eq!(
        served.rows[..]
            .iter()
            .filter(|(_, held)| held.is_none())
            .count(),
        1
    );
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(T0 + MIN_LENGTH_MS, vec![resume]);
    let run = resumed(&result, request);
    assert_eq!(run.outcome, Outcome::Done(Vec::new()));
    assert_eq!(ended(&reads.record(id)), &Outcome::Done(30u64.encode()));
    let mut public_args = (AGENT, READER).encode();
    public_args.extend(keys.encode());
    let arguments = keys.encode();
    assert_eq!(
        run.attests,
        [Attest {
            program: ProgramHash::of(&kernel("reader", "sum_entries")),
            window: Some(WINDOW),
            witness_input: [arguments, served.encode()].concat(),
            output: 30u64.encode(),
            public_args,
            roots: vec![RootRead {
                kind: RootKind::Space,
                space: SPACE,
                window: WINDOW,
                root: space_root(&SPACE, WINDOW, &served.rep_root),
            }],
        }]
    );
    assert_eq!(
        space_root(&SPACE, WINDOW, &served.rep_root),
        vos_wire::vos_anchor::space_root(&SPACE, WINDOW, &served.rep_root)
    );
    assert!(
        reads.node.get(&keys::request(WINDOW, request)).is_none(),
        "the request answered"
    );
}

/// A kernel that reads a row its workflow's read did not name traps: the
/// workflow sees the attest fail, and nothing is stated.
#[test]
fn a_key_outside_the_read_set_traps() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let id = reads.start(T0 + 10, "sum_reading", (vec![1u64, 2], vec![1u64]));
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(T0 + MIN_LENGTH_MS, vec![resume]);
    assert!(resumed(&result, request).attests.is_empty());
    assert_eq!(ended(&reads.record(id)), &failed_with(AttestError::Failed));
}

/// Served rows the kernel's prologue refuses, though the agent serves them
/// as the request's: a row's value changed, the rows' proof tampered, the
/// agent's root another. Each traps, and the workflow sees the attest
/// fail. The close's parts tampered, the space path, the representative's
/// root, a representative's tree without the agent's row, or the leaf's
/// salt, the agent does not serve, as not the close it holds: the workflow
/// sees the read unserved, and the kernel run on them traps all the same.
/// The rows as they are attest.
#[test]
fn a_tampered_witness_traps_the_kernel() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let tampers: [(Change, AttestError); 7] = [
        (
            ("a row's value", |served| {
                served.rows[0].1.as_mut().unwrap().1[0] ^= 1;
            }),
            AttestError::Failed,
        ),
        (
            ("the rows' proof", |served| {
                let last = served.rows_proof.len() - 1;
                served.rows_proof[last] ^= 1;
            }),
            AttestError::Failed,
        ),
        (
            ("the agent's root", |served| served.agent_root[0] ^= 1),
            AttestError::Failed,
        ),
        (
            ("the space path", |served| {
                let last = served.space_path.len() - 1;
                served.space_path[last] ^= 1;
            }),
            AttestError::Unserved,
        ),
        (
            ("the representative's root", |served| {
                served.rep_root[0] ^= 1
            }),
            AttestError::Unserved,
        ),
        (
            ("the representative's row", |served| {
                let other = AgentId(AGENT.0 + 1);
                let (root, _, path) = representative(
                    &[(other, served.window, served.agent_root)],
                    (served.agent, served.window),
                );
                served.rep_root = root;
                served.space_path = path;
            }),
            AttestError::Unserved,
        ),
        (
            ("the leaf's salt", |served| served.rep_salt[0] ^= 1),
            AttestError::Unserved,
        ),
    ];
    let kernel = kernel("reader", "sum_entries");
    for (at, ((name, tamper), error)) in (T0 + 10..).step_by(20).zip(tampers) {
        let id = reads.start(at, "sum_at_cut", vec![1u64, 2]);
        let (request, read) = reads.asked(WINDOW, id, 0);
        let mut served = reads.served(WINDOW, &read);
        tamper(&mut served);
        let input = [vec![1u64, 2].encode(), served.encode()].concat();
        assert_eq!(
            run_kernel(&kernel, &input, 1 << 32).err(),
            Some(Failure::Trapped),
            "{name}"
        );
        let resume = reads.resume(WINDOW, request, Some(&served));
        let result = reads.batch(at + 10, vec![resume]);
        assert!(resumed(&result, request).attests.is_empty(), "{name}");
        assert_eq!(ended(&reads.record(id)), &failed_with(error), "{name}");
    }
    let id = reads.start(T0 + 500, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let resume = reads.resume(WINDOW, request, Some(&served));
    reads.batch(T0 + 510, vec![resume]);
    assert_eq!(ended(&reads.record(id)), &Outcome::Done(30u64.encode()));
}

/// The kernel itself, run on the witness input of a read: its served rows
/// claimed at another window, whose representative's row the path does not
/// prove, or holding a row of another instance, under the reader's prefix
/// no more, each trap; as they are, it returns its statement's parts, their
/// io-hash the one it leaves.
#[test]
fn the_kernel_traps_on_another_window_or_instance() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64, 2]);
    let (_, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let kernel = kernel("reader", "sum_entries");
    let arguments = vec![1u64, 2].encode();
    let run = |served: &Served| {
        let input = [arguments.clone(), served.encode()].concat();
        run_kernel(&kernel, &input, 1 << 32)
    };
    let ran = run(&served).expect("the rows as served");
    let parts = vos_wire::result::KernelReturn::decode(&ran.output)
        .unwrap()
        .0;
    assert_eq!(parts.output, 30u64.encode());
    assert_eq!(parts.io_hash(), ran.io_hash);

    let mut later = served.clone();
    later.window = WINDOW + 1;
    assert_eq!(run(&later).err(), Some(Failure::Trapped), "another window");

    // The rows of instance 6, its own tree and proof, served as the
    // reader's.
    let mut other = served.clone();
    let rows: Vec<(Vec<u8>, Vec<u8>)> = served
        .rows
        .iter()
        .map(|(key, held)| {
            let mut key = key.clone();
            key[1..5].copy_from_slice(&6u32.to_be_bytes());
            (key, held.as_ref().unwrap().1.clone())
        })
        .collect();
    let keys_of: Vec<Vec<u8>> = rows.iter().map(|(key, _)| key.clone()).collect();
    let (store, root) = tree(&SEED, rows.clone());
    other.agent_root = root;
    other.rows = rows
        .iter()
        .map(|(key, value)| {
            let salt = vos_tree::salt(&Blake2b, &SEED, key);
            (key.clone(), Some((salt, value.clone())))
        })
        .collect();
    other.rows_proof = BatchProof::generate(&store, &keys_of).unwrap().encode();
    let (rep_root, rep_salt, space_path) =
        representative(&[(AGENT, WINDOW, root)], (AGENT, WINDOW));
    other.rep_root = rep_root;
    other.rep_salt = rep_salt;
    other.space_path = space_path;
    assert_eq!(
        run(&other).err(),
        Some(Failure::Trapped),
        "another instance's rows"
    );
}

/// What a `Resume` serves the agent runs no kernel on unless it is the
/// request's: within the target's cap, of this agent and its space, of the
/// request's window, instance and rows, in order. Anything else, and none,
/// resumes the workflow unserved, stating nothing.
#[test]
fn the_agent_serves_only_the_request_it_awaits() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let mismatches: [Change; 7] = [
        ("another window", |served| served.window += 1),
        ("another agent", |served| {
            served.agent = AgentId(AGENT.0 + 1)
        }),
        ("another instance", |served| served.instance = InstanceId(6)),
        ("another space", |served| served.space = SpaceId([1; 32])),
        ("a row fewer", |served| {
            served.rows.pop();
        }),
        ("another row", |served| {
            served.rows[0].0 = entry_rows(&[77])[0].clone();
        }),
        ("past the cap", |served| {
            served.rows_proof = vec![0; cap::SERVED];
        }),
    ];
    // And a read served nothing.
    let cases = mismatches.into_iter().map(Some).chain([None]);
    for (at, case) in (T0 + 10..).step_by(20).zip(cases) {
        let id = reads.start(at, "sum_at_cut", vec![1u64, 2]);
        let (request, read) = reads.asked(WINDOW, id, 0);
        let mut served = reads.served(WINDOW, &read);
        let (name, served) = match case {
            Some((name, change)) => {
                change(&mut served);
                (name, Some(served))
            }
            None => ("none", None),
        };
        let resume = reads.resume(WINDOW, request, served.as_ref());
        let result = reads.batch(at + 10, vec![resume]);
        assert!(resumed(&result, request).attests.is_empty(), "{name}");
        assert_eq!(
            ended(&reads.record(id)),
            &failed_with(AttestError::Unserved),
            "{name}"
        );
    }
}

/// The agent refuses an ask at once, the workflow going on in the same
/// step: in an agent of no space; of rows named twice; of more rows than a
/// read names.
#[test]
fn an_ask_is_refused_at_once() {
    let mut spaceless = Reads::new(Target::Vos, SpaceId::NONE);
    let id = spaceless.start(T0, "sum_at_cut", vec![1u64]);
    assert_eq!(
        ended(&spaceless.record(id)),
        &failed_with(AttestError::NoSpace)
    );
    let mut reads = Reads::with(&[(1, 10)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64, 1]);
    assert_eq!(ended(&reads.record(id)), &failed_with(AttestError::Reads));
    let many: Vec<u64> = (0..defaults::MAX_READS as u64 + 1).collect();
    let id = reads.start(T0 + 20, "sum_at_cut", many);
    assert_eq!(ended(&reads.record(id)), &failed_with(AttestError::Reads));
    let fewest: Vec<u64> = (0..defaults::MAX_READS as u64).collect();
    let id = reads.start(T0 + 30, "sum_at_cut", fewest);
    assert!(matches!(
        reads.record(id).state,
        WorkflowState::Attesting { .. }
    ));
}

/// A read no `Resume` serves by its deadline, `B_{w+3}`, ends
/// `NotClosed` at the deadline's step, its request gone; a `Resume` past it
/// resumes nothing.
#[test]
fn a_read_not_served_by_its_deadline_ends_not_closed() {
    let mut reads = Reads::with(&[(1, 10)]);
    let id = reads.start(T0 + 10, "sum_at_cut", vec![1u64]);
    let (request, read) = reads.asked(WINDOW, id, 0);
    let deadline = CLOCK.boundary(WINDOW + defaults::READ_WINDOWS).unwrap();
    let early = reads.node.sweep(deadline - 1);
    reads.batch(deadline - 1, vec![early]);
    assert!(matches!(
        reads.record(id).state,
        WorkflowState::Attesting { .. }
    ));
    let sweep = reads.node.sweep(deadline);
    reads.batch(deadline, vec![sweep]);
    assert_eq!(
        ended(&reads.record(id)),
        &failed_with(AttestError::NotClosed)
    );
    assert!(reads.node.get(&keys::request(WINDOW, request)).is_none());
    let served = reads.served(WINDOW, &read);
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(deadline + 1, vec![resume]);
    let run = resumed(&result, request);
    assert!(run.attests.is_empty() && run.writes.is_empty());
}

/// Two reads, one after the other, each at its own await: each its own
/// request, the second asked in the step the first's answer resumes.
#[test]
fn a_workflow_reads_twice() {
    let mut reads = Reads::with(&[(1, 10), (2, 5)]);
    let id = reads.start(T0 + 10, "sum_twice", vec![1u64, 2]);
    let (first, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let resume = reads.resume(WINDOW, first, Some(&served));
    let next = T0 + MIN_LENGTH_MS;
    reads.batch(next, vec![resume]);
    let (second, read) = reads.asked(WINDOW + 1, id, 1);
    assert!(reads.node.get(&keys::request(WINDOW, first)).is_none());
    let served = reads.served(WINDOW + 1, &read);
    let resume = reads.resume(WINDOW + 1, second, Some(&served));
    reads.batch(next + 10, vec![resume]);
    assert_eq!(
        ended(&reads.record(id)),
        &Outcome::Done((15u64, 15u64).encode())
    );
}

/// Public arguments in their order: a venue first for a `venue_bound`
/// method, then the reader for a `&self` one, then each `#[public]`
/// argument in the method's order, the private ones left out; so a venue's
/// prefix is `public_args[..32]`. A method of none states its output
/// alone.
#[test]
fn public_arguments_come_in_order() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let plain = reads.request("attest_plain", ((VENUE, 9u64, 7u64), (1u8, 2u16, 3u32)));
    let result = reads.batch(T0 + 10, vec![plain]);
    let run = ran(&result.steps[0]);
    assert_eq!(run.outcome, Outcome::Done((49u64, 6u32).encode()));
    let [stamped, ordered] = &run.attests[..] else {
        panic!("two attests: {:?}", run.attests);
    };
    assert_eq!(
        stamped.public_args,
        [VENUE.encode(), 9u64.encode()].concat()
    );
    assert_eq!(&stamped.public_args[..32], &VENUE.0);
    assert_eq!(ordered.public_args, [1u8.encode(), 3u32.encode()].concat());
    for attest in [stamped, ordered] {
        assert_eq!(attest.window, None);
        assert!(attest.roots.is_empty());
    }
    let schema = vos_testkit::programs::schema(&reads.derived.actor);
    let kind = |name: &str| schema.method(reads.method(name)).unwrap().kind;
    assert_eq!(kind("stamped"), Kind::Stating);
    assert_eq!(kind("ordered"), Kind::Stating);
    assert_eq!(kind("sum_entries"), Kind::Reading);

    let name = reads.request("set_name", (4u32, Some(b"ada".to_vec())));
    reads.batch(T0 + 20, vec![name]);
    let id = reads.start(T0 + 30, "name_at_cut", ((VENUE, 11u64), (4u32, vec![1u64])));
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(T0 + 40, vec![resume]);
    let attest = &resumed(&result, request).attests[0];
    assert_eq!(
        attest.public_args,
        [VENUE.encode(), (AGENT, READER).encode(), 11u64.encode()].concat()
    );
    assert_eq!(
        ended(&reads.record(id)),
        &Outcome::Done((Some(b"ada".to_vec()), 10u64).encode())
    );
}

/// An attest at a window's cut counts two against the step's attests: in
/// the step its answer resumes, the workflow's call may make fourteen more
/// on VOS, sixteen in all, and fails with a fifteenth, past the cap.
#[test]
fn an_attest_at_a_cut_counts_two() {
    let mut reads = Reads::with(&[(1, 10)]);
    let most = (cap::VOS.attests - cap::AT_CUT) as u32;
    for (at, (count, fits)) in (T0 + 10..)
        .step_by(20)
        .zip([(most, true), (most + 1, false)])
    {
        let id = reads.start(at, "sum_then_attest", (vec![1u64], count));
        let (request, read) = reads.asked(WINDOW, id, 0);
        let served = reads.served(WINDOW, &read);
        let resume = reads.resume(WINDOW, request, Some(&served));
        let result = reads.batch(at + 10, vec![resume]);
        let run = resumed(&result, request);
        if fits {
            assert_eq!(run.attests.len(), 1 + count as usize);
            assert_eq!(
                ended(&reads.record(id)),
                &Outcome::Done((10u64, count).encode())
            );
        } else {
            assert!(run.attests.is_empty());
            assert_eq!(ended(&reads.record(id)), &Outcome::failed(Failure::Cap));
        }
    }
}

/// On JAM: an ask's arguments past the 2 KiB attest cap are refused at
/// once, `Cap`; a read within it is served and stated as on VOS; served
/// rows past JAM's own cap, 32 KiB, go unserved.
#[test]
fn a_read_on_jam_holds_its_caps() {
    let mut reads = Reads::new(Target::Jam, SPACE);
    let set = reads.request("set_entries", vec![(1u64, Some(10u64)), (2, Some(20))]);
    reads.batch(T0, vec![set]);
    let past: Vec<u64> = (0..cap::JAM.attest as u64 / 8 + 1).collect();
    assert!(past.encode().len() > cap::JAM.attest);
    let id = reads.start(T0 + 10, "sum_at_cut", past);
    assert_eq!(ended(&reads.record(id)), &failed_with(AttestError::Cap));
    let id = reads.start(T0 + 20, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    assert!(served.encode().len() <= cap::JAM.served);
    let resume = reads.resume(WINDOW, request, Some(&served));
    let result = reads.batch(T0 + 30, vec![resume]);
    assert_eq!(resumed(&result, request).attests.len(), 1);
    assert_eq!(ended(&reads.record(id)), &Outcome::Done(30u64.encode()));
    let id = reads.start(T0 + 40, "sum_at_cut", vec![1u64, 2]);
    let (request, read) = reads.asked(WINDOW, id, 0);
    let mut served = reads.served(WINDOW, &read);
    served.rows_proof = vec![0; cap::JAM.served];
    let resume = reads.resume(WINDOW, request, Some(&served));
    reads.batch(T0 + 50, vec![resume]);
    assert_eq!(
        ended(&reads.record(id)),
        &failed_with(AttestError::Unserved)
    );
}
