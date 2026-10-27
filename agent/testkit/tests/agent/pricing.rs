//! What the agent spends serving a step against what the step is charged:
//! every operation's price, and the reserve a step keeps for the agent's
//! own work.

use vos_testkit::Testkit;
use vos_wire::abi::cap;
use vos_wire::defaults;
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::result::{Outcome, WorkResult};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

use crate::common::{
    AGENT, ALICE, CALLER, COUNTER, LEDGER, Node, OUTER_GAS, counter_only, install, ran, ran_done,
    request, setup,
};

/// A refine's gas is the agent's serving plus its steps' gas, which holds
/// what the actors run and what they are charged. Over a phase of one kind
/// of operation, the slope of their difference is what the agent spends per
/// operation beyond its charge. Measured at a handler's limit, after the
/// writes that make the agent's overlays largest (a step's own, and a
/// batch's worth before it), it must leave a fifth of the charge spare.
#[test]
fn every_operation_pays_for_its_serving() {
    use vos_wire::abi::price::{
        self, ATTEST, GET, INPUT, KEY_BYTE, LOG, MACHINE, OPERATION, PER_BYTE, PUT, RANDOM, SCAN,
        SEND,
    };
    let (actors, node, _, _) = setup();
    let ops = actors.method(COUNTER, "ops");
    let total = actors.method(LEDGER, "total");
    let audits = actors.method(LEDGER, "audits");
    // Steps in one batch, each a request; the agent's gas beyond theirs.
    let unpaid = |steps: Vec<(InstanceId, MethodId, Vec<u8>)>| -> i64 {
        let inputs = steps
            .into_iter()
            .zip(1..)
            .map(|((instance, method, arguments), sequence)| {
                request(ALICE, sequence, instance, method, arguments)
            })
            .collect();
        node.agent_gas(inputs)
    };
    let ops_step =
        |phases: Vec<(u8, u32, u32)>| (COUNTER, ops, (phases, (LEDGER.0, total.0)).encode());
    // Eight steps of 1,500 writes each: the batch's committed overlay.
    let batch = |measured: Vec<(u8, u32, u32)>| {
        let mut steps: Vec<_> = (0..8)
            .map(|step| ops_step(vec![(3, 100_000 + step * 1500, 1500)]))
            .collect();
        steps.push(ops_step(measured));
        steps
    };
    let bytes = |count: u64| count * PER_BYTE;
    // A scan as large as a scan may be returns this many rows of a 1 KiB
    // key and a byte, each framed by two lengths, and is charged for each
    // byte it returns.
    let row = 4 + 1024 + 4 + 1;
    let rows = (cap::SCAN / row) as u64;
    let full_scan = rows * row as u64 * PER_BYTE + rows * 1024 * KEY_BYTE;
    // A row operation's key, copied and transformed.
    let key = |len: u64| len * (PER_BYTE + KEY_BYTE);
    // What `input` copies: the arguments of the step that measures it.
    let input_len = ops_step(vec![(13, 0, 1000)]).2.len() as u64;
    // (name, steps before in the batch, phases before, kind, count, charge per operation)
    type Case = (&'static str, bool, Vec<(u8, u32, u32)>, u8, u32, u64);
    let cases: Vec<Case> = vec![
        ("an unserved id", false, vec![], 0, 1000, OPERATION),
        ("now", false, vec![], 1, 1000, OPERATION),
        ("random", false, vec![], 8, 1000, RANDOM + bytes(32)),
        ("caller", false, vec![], 9, 1000, price::CALLER + bytes(33)),
        ("log", false, vec![], 10, 1000, LOG + bytes(9)),
        ("self_id", false, vec![], 12, 1000, OPERATION),
        ("input", false, vec![], 13, 1000, INPUT + bytes(input_len)),
        ("get of an absent key", false, vec![], 2, 1000, GET + key(4)),
        (
            "get after 1,000 writes",
            false,
            vec![(3, 0, 1000)],
            2,
            1000,
            GET + key(4) + bytes(1),
        ),
        (
            "get after a batch of writes",
            true,
            vec![],
            2,
            1000,
            GET + key(4),
        ),
        (
            "put after 500 writes",
            false,
            vec![(3, 0, 500)],
            3,
            900,
            PUT + key(4) + bytes(1),
        ),
        (
            "put after a batch of writes",
            true,
            vec![],
            3,
            1400,
            PUT + key(4) + bytes(1),
        ),
        (
            "delete after 500 writes",
            false,
            vec![(3, 0, 500)],
            11,
            500,
            PUT + key(4),
        ),
        (
            "put of 4 KiB",
            false,
            vec![],
            7,
            60,
            PUT + key(4) + bytes(4096),
        ),
        (
            "get of a 1 KiB key after 240 such writes",
            false,
            vec![(15, 0, 240)],
            14,
            240,
            GET + key(1024) + bytes(1),
        ),
        (
            "put of a 1 KiB key",
            false,
            vec![(15, 0, 120)],
            15,
            120,
            PUT + key(1024) + bytes(1),
        ),
        // Escaped, a zero key doubles: a step's write cap holds about 125.
        (
            "get of a 1 KiB zero key after 120 such writes",
            false,
            vec![(17, 0, 120)],
            16,
            120,
            GET + key(1024) + bytes(1),
        ),
        (
            "put of a 1 KiB zero key",
            false,
            vec![(17, 0, 60)],
            17,
            60,
            PUT + key(1024) + bytes(1),
        ),
        (
            "a full scan of 1 KiB zero keys",
            false,
            vec![(17, 0, 80)],
            18,
            8,
            SCAN + full_scan,
        ),
        (
            "scan after 1,000 writes",
            false,
            vec![(3, 0, 1000)],
            4,
            300,
            SCAN,
        ),
        ("scan after a batch of writes", true, vec![], 4, 300, SCAN),
        ("call", false, vec![], 6, 900, MACHINE),
    ];
    let mut short = Vec::new();
    for (name, batched, before, kind, count, charge) in cases {
        let mut with = before.clone();
        let start = if matches!(kind, 3 | 15 | 17) {
            before.iter().map(|phase| phase.2).sum()
        } else {
            0
        };
        with.push((kind, start, count));
        let (with, before) = if batched {
            (batch(with), batch(before))
        } else {
            (vec![ops_step(with)], vec![ops_step(before)])
        };
        let beyond = (unpaid(with) - unpaid(before)) / i64::from(count);
        let cost = charge as i64 + beyond;
        println!("{name}: charged {charge}, costs the agent {cost}");
        if cost > charge as i64 * 4 / 5 {
            short.push(name);
        }
    }
    // A get and a scan through 61 call frames: a get probes every frame,
    // a scan merges them.
    let mut deep = Node::new();
    let mut kit = Testkit::new(AGENT);
    actors.install(&mut deep, &mut kit);
    let caller = deep.add(&actors.caller);
    let installs = (100..170)
        .map(|instance| install(InstanceId(instance), caller))
        .collect();
    deep.batch(1, installs);
    let dive = actors.method(CALLER, "dive");
    let at_depth = |kind: u8, count: u32| -> i64 {
        let arguments = ((101u32, 60u32), (kind, count)).encode();
        deep.agent_gas(vec![request(ALICE, 1, InstanceId(100), dive, arguments)])
    };
    for (name, kind, count, charge) in [
        ("get through 61 frames", 0, 1000, GET + key(4)),
        ("scan through 61 frames", 1, 300, SCAN),
    ] {
        let cost = charge as i64 + (at_depth(kind, count) - at_depth(kind, 0)) / i64::from(count);
        println!("{name}: charged {charge}, costs the agent {cost}");
        if cost > charge as i64 * 4 / 5 {
            short.push(name);
        }
    }
    // A step sends at most `cap::MESSAGES`: measured over eight steps, so
    // the heap's growth weighs on more sends than one step's.
    let sends = |count: u32| (0..8).map(|_| ops_step(vec![(5, 0, count)])).collect();
    let count = 8 * cap::MESSAGES as i64;
    let cost = SEND as i64 + (unpaid(sends(cap::MESSAGES as u32)) - unpaid(sends(0))) / count;
    println!("send: charged {SEND}, costs the agent {cost}");
    if cost > SEND as i64 * 4 / 5 {
        short.push("send");
    }
    let attest = |count: u32| vec![(LEDGER, audits, count.encode())];
    let cost = ATTEST as i64 + (unpaid(attest(16)) - unpaid(attest(0))) / 16;
    println!("attest: charged {ATTEST}, costs the agent {cost}");
    if cost > ATTEST as i64 * 4 / 5 {
        short.push("attest");
    }
    assert!(short.is_empty(), "priced without a fifth spare: {short:?}");
}

/// The agent's own work leaves a fifth of what it takes spare at its most:
/// installing a program whose schema is as large as a schema may be
/// (`INSTALL_RESERVE`), and a step's first read of that installed record
/// (`STEP_RESERVE` and the record's `RECORD_BYTE`).
#[test]
fn the_install_reserve_and_record_price_cover_the_largest_install() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    use vos_wire::abi::Kind;
    use vos_wire::schema::{MAX_LEN, MethodSchema};
    let methods: Vec<MethodSchema> = (1..=1000u32)
        .map(|id| MethodSchema {
            id: MethodId(id),
            name: format!("{id:0>53}").into_bytes(),
            kind: Kind::Command,
            role: None,
            gas: None,
            linearizable: false,
            credential: None,
        })
        .collect();
    let schema = Schema {
        methods,
        credentials: false,
    };
    let section = schema.section();
    assert!(section.len() - 8 <= MAX_LEN && section.len() - 8 > MAX_LEN - 4096);
    // Return to the halt address at once.
    let big = build_standard_program(&StandardProgram {
        ro_data: section,
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code: vec![50, 0],
            bitmask: vec![1, 0],
        },
    })
    .unwrap();
    let (_, mut node, _, mut sessions) = setup();
    let program = node.add(&big);
    let big_instance = InstanceId(50);
    let empty = node.agent_gas(vec![]);
    let install_big = install(big_instance, program);
    let installing = node.agent_gas(vec![install_big.clone()]) - empty;
    let result = node.batch(1, vec![install_big]);
    assert!(matches!(ran(&result.steps[0]).outcome, Outcome::Done(_)));
    let first_read = sessions.request(ALICE, big_instance, MethodId(1), ());
    let reading = node.agent_gas(vec![first_read]) - empty;
    let record = node.state[&vos_wire::keys::installed(big_instance)].len() as u64;
    let taken = defaults::STEP_RESERVE + defaults::RECORD_BYTE * record;
    println!("install {installing}, first read of {record} bytes and run {reading} of {taken}");
    assert!(
        installing <= (defaults::INSTALL_RESERVE * 4 / 5) as i64,
        "install: {installing}"
    );
    assert!(reading <= (taken * 4 / 5) as i64, "first read: {reading}");
}

/// The agent's own work on each kind of input leaves a fifth of its reserve
/// spare, on a VOS host and on a JAM host, which loads every machine from
/// its blob: a request or a message running a handler that does next to
/// nothing, beyond its first read of the installed record, which that pays
/// for; an acknowledgement; a message failed in refine; and a sweep
/// collecting as many sessions as a sweep may.
#[test]
fn the_reserves_cover_the_agents_own_work() {
    use vos_wire::batch::{Body, Input, Message};
    use vos_wire::ids::{AgentId, Session};
    for (host, node) in [("VOS", Node::new()), ("JAM", Node::jam(true))] {
        let (actors, mut node) = counter_only(node);
        let value = actors.method(COUNTER, "value");
        let empty = node.agent_gas(vec![]);
        let record = node.state[&vos_wire::keys::installed(COUNTER)].len() as u64;
        let check = |name: &str, cost: i64, taken: u64| {
            println!("{host}: {name} costs the agent {cost} of {taken}");
            assert!(cost <= (taken * 4 / 5) as i64, "{host}: {name}");
        };
        // Each a steps' worth of inputs: the first's cost, then each other's.
        let costs = |make: &dyn Fn(u64) -> Input| {
            let one = node.agent_gas(vec![make(1)]) - empty;
            let many = node.agent_gas((1..=21).map(make).collect()) - empty;
            (one, (many - one) / 20)
        };
        let (first, each) = costs(&|sequence| request(ALICE, sequence, COUNTER, value, vec![]));
        check(
            "a request's first",
            first,
            defaults::STEP_RESERVE + defaults::RECORD_BYTE * record,
        );
        check("a request", each, defaults::STEP_RESERVE);
        let call = |sequence| {
            Input::Message(Message {
                from: AgentId(5),
                sequence,
                body: Body::Call {
                    instance: COUNTER,
                    method: value,
                    arguments: vec![],
                    awaiting: None,
                },
            })
        };
        check("a message", costs(&call).1, defaults::STEP_RESERVE);
        // Inputs that run no handler: their cost is the refine's beyond
        // the empty one's, every step's gas being 0.
        let plain = |inputs: Vec<Input>| {
            let work = node.work(1, inputs);
            node.run_refine(&work, OUTER_GAS).gas_used as i64
        };
        let none = plain(vec![]);
        let acks = |count: u32| {
            (1..=count)
                .map(|to| Input::Ack {
                    to: AgentId(to),
                    sequence: 1,
                })
                .collect::<Vec<_>>()
        };
        check(
            "an ack",
            (plain(acks(21)) - none) / 21,
            defaults::INPUT_RESERVE,
        );
        let failed = (1..=21)
            .map(|sequence| Input::Failed {
                from: AgentId(5),
                sequence,
                awaiting: None,
            })
            .collect();
        check(
            "a failed message",
            (plain(failed) - none) / 21,
            defaults::INPUT_RESERVE,
        );
        // Sessions created long ago, more than a sweep collects.
        let bucket = defaults::SESSION_BUCKET_MS;
        let created = (0..2 * defaults::SWEEP_LIMIT as u8)
            .map(|name| {
                let session = Session {
                    key: [name; 32],
                    name: [name; 16],
                    t0: 10 * bucket,
                };
                crate::common::increment_in(&actors, session, 1)
            })
            .collect();
        node.batch(10 * bucket, created);
        let later = 10 * bucket + defaults::SESSION_EXPIRY_MS + 2 * bucket;
        let sweeping = node.run_refine(&node.work(later, vec![node.sweep(later)]), OUTER_GAS);
        let swept = WorkResult::decode(&sweeping.output_bounded(cap::OUTPUT).unwrap())
            .unwrap()
            .0;
        assert!(
            matches!(&swept.steps[0], vos_wire::result::Step::Swept { due, .. } if due.len() == defaults::SWEEP_LIMIT)
        );
        let idle = node
            .run_refine(&node.work(later, vec![]), OUTER_GAS)
            .gas_used;
        check(
            "a full sweep",
            (sweeping.gas_used - idle) as i64,
            defaults::SWEEP_RESERVE,
        );
        // And as many binding digests as a sweep forgets beside them.
        // Due before the sessions, so the sweep lists both its counts' worth.
        for index in 0..defaults::SWEEP_BINDINGS as u32 {
            let mut binding = [0u8; 32];
            binding[..4].copy_from_slice(&index.to_le_bytes());
            let row = vos_wire::keys::due(1, vos_wire::keys::Due::Binding(binding));
            node.state.insert(row, vos_wire::records::stored(&[]));
            let kept = vos_wire::keys::binding(&binding);
            node.state
                .insert(kept, vos_wire::records::stored(&later.encode()));
        }
        let sweeping = node.run_refine(&node.work(later, vec![node.sweep(later)]), OUTER_GAS);
        let swept = WorkResult::decode(&sweeping.output_bounded(cap::OUTPUT).unwrap())
            .unwrap()
            .0;
        assert!(matches!(
            &swept.steps[0],
            vos_wire::result::Step::Swept { due, bindings }
                if due.len() == defaults::SWEEP_LIMIT && bindings.len() == defaults::SWEEP_BINDINGS
        ));
        check(
            "a full sweep with bindings",
            (sweeping.gas_used - idle) as i64,
            defaults::SWEEP_RESERVE,
        );
    }
}

/// An actor's precompile call exits to the agent, which serves it: the
/// actor pays the node's price for it on every host, and the agent's own
/// work serving it, its bounce (the exit, the copies, and the compression,
/// natively on a VOS node and in software on JAM), leaves a fifth of what
/// the agent accounts for it spare (`PRECOMPILE_SERVING` for a BLAKE2b
/// compression, `POSEIDON2_SERVING` for a Poseidon2 one).
#[test]
fn serving_a_precompile_costs_the_agent_its_bounce() {
    use vos_wire::abi::precompile::{BLAKE2B_COMPRESS, POSEIDON2, price, serving};
    for (name, kind, id) in [
        ("BLAKE2b", 19u8, BLAKE2B_COMPRESS),
        ("Poseidon2", 20, POSEIDON2),
    ] {
        let price = price(id).unwrap();
        let mut actor_gas = Vec::new();
        for (host, node) in [("VOS", Node::new()), ("JAM", Node::jam(true))] {
            let (actors, node) = counter_only(node);
            let ops = actors.method(COUNTER, "ops");
            // The refine's gas and its step's, with `count` compressions.
            let run = |count: u32| {
                let arguments = (vec![(kind, 0u32, count)], (0u32, 0u32)).encode();
                let work = node.work(1, vec![request(ALICE, 1, COUNTER, ops, arguments)]);
                let invocation = node.run_refine(&work, OUTER_GAS);
                let bytes = invocation.output_bounded(cap::OUTPUT).unwrap();
                let (result, _) = WorkResult::decode(&bytes).unwrap();
                let used = ran_done(&result.steps[0]).gas_used;
                (invocation.gas_used as i64, used as i64)
            };
            let ((refine, used), (refine_without, used_without)) = (run(1000), run(0));
            let per_call = (used - used_without) / 1000;
            let bounce = price as i64 + (refine - used - (refine_without - used_without)) / 1000;
            println!(
                "{host}: a {name} compression costs the actor {per_call}, {price} of it its \
                 price; serving it costs the agent {bounce}"
            );
            actor_gas.push(per_call);
            assert!(
                bounce <= (serving(id) * 4 / 5) as i64,
                "{host}, {name}: {bounce}"
            );
        }
        assert_eq!(
            actor_gas[0], actor_gas[1],
            "{name}: the actor pays the same on both"
        );
    }
}

/// What a refine spends before its first step, decoding its batch, and on
/// finishing it, leaves a fifth spare of what a node gives it for them
/// beyond its budget (`batch_start`): the start, a share for each input,
/// one for each byte of its arguments and one for each kernel its installs
/// name. Measured with a budget of nothing, on batches of many small
/// inputs, of large arguments and of installs of the most kernels, their
/// shapes at derive's classes and at the most classes a shape has.
#[test]
fn the_start_reserves_cover_decoding_a_batch() {
    use vos_testkit::programs::{derivation, derived, package};
    use vos_wire::abi::cap::Target;
    use vos_wire::batch::{Admin, Body, Input, Message};
    use vos_wire::ids::{AgentId, InstanceId};
    let (actors, node, _, _) = setup();
    let increment = actors.method(COUNTER, "increment");
    let requests = |count: u64, len: usize| -> Vec<Input> {
        (1..=count)
            .map(|sequence| request(ALICE, sequence, COUNTER, increment, vec![7; len]))
            .collect()
    };
    let messages = |count: u64, len: usize| -> Vec<Input> {
        (1..=count)
            .map(|sequence| {
                Input::Message(Message {
                    from: AgentId(5),
                    sequence,
                    body: Body::Call {
                        instance: COUNTER,
                        method: increment,
                        arguments: vec![7; len],
                        awaiting: None,
                    },
                })
            })
            .collect()
    };
    let wide = derivation(&package("wide"), &derived("wide"));
    let mut widest = wide.clone();
    for kernel in &mut widest.kernels {
        let class = kernel.shape.classes[0];
        kernel
            .shape
            .classes
            .resize(vos_wire::records::MAX_CLASSES, class);
    }
    let installs = |count: u32, derivation: &vos_wire::records::Derivation| -> Vec<Input> {
        (1..=count)
            .map(|instance| {
                Input::Admin(Admin::Install {
                    instance: InstanceId(100 + instance),
                    derivation: derivation.clone(),
                    roles: vec![],
                    target: Target::Vos,
                    space: vos_wire::SpaceId::NONE,
                    clock: vos_wire::WindowClock::DEFAULT,
                })
            })
            .collect()
    };
    for (name, inputs) in [
        ("no input", vec![]),
        ("a request", requests(1, 8)),
        ("256 requests", requests(256, 8)),
        ("256 messages", messages(256, 8)),
        ("a request of 60 KB", requests(1, 60_000)),
        ("16 requests of 60 KB", requests(16, 60_000)),
        ("6 installs of 33 kernels", installs(6, &wide)),
        (
            "6 installs of 33 kernels at the most classes",
            installs(6, &widest),
        ),
        ("a sweep of its most rows", vec![most_swept()]),
    ] {
        let work = node.budgeted_work(1, [0; 32], 0, inputs);
        let arguments = node.arguments(&work).len() as u64;
        let invocation = node.run_refine(&work, OUTER_GAS);
        let (result, _) =
            WorkResult::decode(&invocation.output_bounded(cap::OUTPUT).unwrap()).unwrap();
        assert!(result.steps.is_empty(), "{name}: nothing dispatched");
        let kept = defaults::batch_start(work.batch().unwrap(), arguments as usize);
        println!("{name}: {} of {kept}", invocation.gas_used);
        assert!(invocation.gas_used <= kept * 4 / 5, "{name}");
    }
}

/// What the agent spends on a workflow's step beyond its gas leaves a
/// fifth spare of what it accounts for it: its reserve, each page its
/// program may write, armed every step, each page the step writes, and
/// each page it restores (`WORKFLOW_RESERVE`, `ARM_PAGE`, `WRITTEN_PAGE`,
/// `RESTORED_PAGE`). Measured on a VOS node and on a JAM node, whose
/// agent hashes in software, from steps that write and restore up to
/// 2 MiB of pages, some of them random, which compress the least.
#[test]
fn the_workflow_reserves_cover_the_agents_own_work() {
    use crate::workflows::Flows;
    use vos_wire::result::{Run, Step};
    /// A step's measure: the agent's gas beyond the step's, the pages its
    /// program may write, those it stored, and those it restored.
    type Measure = (u64, u64, u64, u64);
    let run = |step: &Step| match step {
        Step::Ran(run) => run.clone(),
        other => panic!("{other:?}"),
    };
    let stored = |run: &Run| run.pages.iter().filter(|page| page.hash.is_some()).count() as u64;
    type Host = (&'static str, fn() -> Node);
    let hosts: [Host; 2] = [("VOS", Node::new), ("JAM", || Node::jam(true))];
    for (host, node) in hosts {
        // A workflow's first step, after its start, and its next, after a
        // sweep, each beside its batch's other step's reserve.
        let steps = |name: &str, arguments: Vec<u8>| -> [(Measure, u64); 2] {
            let mut flows = Flows::new(node());
            let idle = flows.measured(1, vec![]).1;
            let start = flows.start_bytes(name, arguments);
            let (result, gas) = flows.measured(1, vec![start]);
            let first = run(&result.steps[1]);
            let record = flows.record(0);
            let writable = u64::from(record.writable);
            let held = record.snapshot.map_or(0, |snapshot| snapshot.pages.len()) as u64;
            let measure = (gas - idle - first.gas_used, writable, stored(&first), 0);
            let started = (measure, defaults::STEP_RESERVE);
            let sweep = flows.sweeping(1);
            let (result, gas) = flows.measured(1, vec![sweep]);
            let second = run(&result.steps[1]);
            let measure = (
                gas - idle - second.gas_used,
                writable,
                stored(&second),
                held,
            );
            [started, (measure, defaults::SWEEP_RESERVE)]
        };
        let accounted = |(_, writable, written, restored): Measure| {
            defaults::WORKFLOW_RESERVE
                + writable * defaults::ARM_PAGE
                + written * defaults::WRITTEN_PAGE
                + restored * defaults::RESTORED_PAGE
        };
        let cases = [
            ("nap", 1u64.encode()),
            ("hog", 0u32.encode()),
            ("hog", (1u32 << 20).encode()),
            ("hog", (2u32 << 20).encode()),
            // Random words, a few pages sorted a step.
            ("compute", (1u32 << 17, 64u32).encode()),
            ("compute", (1u32 << 18, 64u32).encode()),
        ];
        for (name, arguments) in cases {
            for (which, (measure, beside)) in
                ["first", "second"].into_iter().zip(steps(name, arguments))
            {
                let (own, writable, written, restored) = measure;
                let kept = accounted(measure) + beside;
                println!(
                    "{host} {name} {which}: {own} for {writable} writable, {written} written, \
                     {restored} restored; {kept} accounted"
                );
                assert!(own <= kept * 4 / 5, "{host} {name} {which}");
            }
        }
    }
}

/// A workflow's pauses pay for their serving, a fifth spare
/// (`price::PAUSE`): a request with its arguments, and a wait for a
/// result, against a sleep, in steps that write the same memory. A sleep's
/// own serving reads two registers, and is taken at a register-only
/// operation's price.
#[test]
fn a_pause_pays_for_its_serving() {
    use crate::workflows::Flows;
    use vos_wire::abi::price::{OPERATION, PAUSE, PER_BYTE};
    use vos_wire::result::Step;
    // The agent's gas beyond its steps' for a start and its first step.
    let own = |kind: u8, len: u32| -> i64 {
        let mut flows = Flows::new(Node::new());
        let idle = flows.measured(1, vec![]).1;
        let start = flows.start("probe", (kind, 9u32, len));
        let (result, gas) = flows.measured(1, vec![start]);
        let Step::Ran(run) = &result.steps[1] else {
            panic!("{:?}", result.steps[1]);
        };
        gas as i64 - idle as i64 - run.gas_used as i64
    };
    for len in [0u32, 60_000] {
        let sleep = own(0, len);
        // The echo's arguments, a byte vector, as the request copies them.
        let arguments = u64::from(len) + 4;
        for (name, kind, charge) in [
            ("a request", 1, PAUSE + PER_BYTE * arguments),
            ("a wait for a result", 2, PAUSE),
        ] {
            let cost = own(kind, len) - sleep + charge as i64 - PAUSE as i64 + OPERATION as i64;
            println!("{name} of {len} bytes: charged {charge}, costs the agent {cost}");
            assert!(cost <= (charge * 4 / 5) as i64, "{name}, {len} bytes");
        }
    }
}

/// A section's open and its close pay for their serving, a fifth spare
/// (`price::SECTION` each): a workflow's thousands of empty sections
/// against none.
#[test]
fn a_section_pays_for_its_serving() {
    use crate::workflows::Flows;
    use vos_wire::abi::price::SECTION;
    use vos_wire::result::Step;
    // The agent's gas beyond its steps' for a start and its first step.
    let own = |count: u32| -> i64 {
        let mut flows = Flows::new(Node::new());
        let idle = flows.measured(1, vec![]).1;
        let start = flows.start("sections", count);
        let (result, gas) = flows.measured(1, vec![start]);
        let Step::Ran(run) = &result.steps[1] else {
            panic!("{:?}", result.steps[1]);
        };
        gas as i64 - idle as i64 - run.gas_used as i64
    };
    let count = 4_000;
    let charge = 2 * SECTION;
    let cost = charge as i64 + (own(count) - own(0)) / i64::from(count);
    println!("a section: charged {charge}, costs the agent {cost}");
    assert!(cost <= (charge * 4 / 5) as i64, "{cost} of {charge}");
}

/// A sweep listing the most rows one may: its sessions' and workflows', and
/// its bindings' beside them.
fn most_swept() -> vos_wire::batch::Input {
    use vos_wire::ids::{SessionId, WorkflowId};
    use vos_wire::keys::Due;
    let others = (0..defaults::SWEEP_LIMIT as u64).map(|id| match id % 2 {
        0 => (id, Due::Session(SessionId(id))),
        _ => (id, Due::Workflow(WorkflowId(id))),
    });
    let bindings = (0..defaults::SWEEP_BINDINGS as u64).map(|id| {
        let mut binding = [0xb1; 32];
        binding[..8].copy_from_slice(&id.to_le_bytes());
        (id, Due::Binding(binding))
    });
    vos_wire::batch::Input::Sweep {
        due: others.chain(bindings).collect(),
    }
}
