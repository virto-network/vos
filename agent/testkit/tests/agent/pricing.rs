//! What the agent spends serving a step against what the step is charged:
//! every operation's price, and the reserve a step keeps for the agent's
//! own work.

use vos_testkit::Testkit;
use vos_wire::Encode;
use vos_wire::abi::cap;
use vos_wire::defaults;
use vos_wire::ids::{InstanceId, MethodId};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

use crate::common::{AGENT, ALICE, CALLER, COUNTER, LEDGER, Node, install, ran, request, setup};

/// A refine's gas is the agent's serving plus its steps' gas, which holds
/// what the actors run and what they are charged. Over a phase of one kind
/// of operation, the slope of their difference is what the agent spends per
/// operation beyond its charge. Measured at a handler's limit, after the
/// writes that make the agent's overlays largest (a step's own, and a
/// batch's worth before it), it must leave a fifth of the charge spare.
#[test]
fn every_operation_pays_for_its_serving() {
    use vos_wire::abi::price::{
        self, GET, KEY_BYTE, LOG, MACHINE, OPERATION, PER_BYTE, PUT, RANDOM, SCAN, SEND,
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
    // (name, steps before in the batch, phases before, kind, count, charge per operation)
    type Case = (&'static str, bool, Vec<(u8, u32, u32)>, u8, u32, u64);
    let cases: Vec<Case> = vec![
        ("an unserved id", false, vec![], 0, 1000, OPERATION),
        ("now", false, vec![], 1, 1000, OPERATION),
        ("random", false, vec![], 8, 1000, RANDOM + bytes(32)),
        ("caller", false, vec![], 9, 1000, price::CALLER + bytes(33)),
        ("log", false, vec![], 10, 1000, LOG + bytes(9)),
        ("self_id", false, vec![], 12, 1000, OPERATION),
        ("input", false, vec![], 13, 1000, OPERATION),
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
        ("call", false, vec![], 6, 1000, MACHINE),
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
    let cost = MACHINE as i64 + (unpaid(attest(16)) - unpaid(attest(0))) / 16;
    println!("attest: charged {MACHINE}, costs the agent {cost}");
    if cost > MACHINE as i64 * 4 / 5 {
        short.push("attest");
    }
    assert!(short.is_empty(), "priced without a fifth spare: {short:?}");
}

/// The agent's own work on a step leaves a fifth of its reserve spare at
/// its most: installing a program whose schema is as large as a schema may
/// be (`INSTALL_RESERVE`), and the first read of that installed record
/// (`STEP_RESERVE`).
#[test]
fn the_step_reserve_covers_the_largest_install() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    use vos_wire::abi::Kind;
    use vos_wire::schema::{MAX_LEN, MethodSchema};
    let methods: Vec<MethodSchema> = (1..=1000u32)
        .map(|id| MethodSchema {
            id: MethodId(id),
            name: format!("{id:0>52}").into_bytes(),
            kind: Kind::Command,
            role: None,
            gas: None,
        })
        .collect();
    let schema = Schema { methods };
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
    println!("install {installing}, first read and run {reading}");
    assert!(
        installing <= (defaults::INSTALL_RESERVE * 4 / 5) as i64,
        "install: {installing}"
    );
    assert!(
        reading <= (defaults::STEP_RESERVE * 4 / 5) as i64,
        "first read: {reading}"
    );
}
