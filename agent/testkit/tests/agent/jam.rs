//! JAM mode against a VOS node. Each batch runs on a VOS node's refine and
//! accumulate, and as a JAM package: simulated on the builder's store,
//! witnessed, refined on the JAM-only host with its imports from emulated
//! DA, accumulated, and its work result applied to the builder's store.
//! The work results are equal byte for byte, the pages equal by hash, the
//! roots continue from package to package, and the builder's rows are the
//! VOS node's, but for what only a VOS node keeps and the page rows.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_jam::builder::POLKAJAM_REFINE_GAS;
use vos_jam::{
    Builder, Chain, Emulated, Error, Fate, Fault, Landed, Refined, Runner, Store, Taken, builder,
    gas,
};
use vos_pvm::PvmBackend;
use vos_testkit::programs::{actor, method};
use vos_tree::{Blake2b, Hash, Hasher, empty_root};
use vos_wire::abi::{Rows, cap};
use vos_wire::batch::{Admin, Answer, Await, Body, Input, Message, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, WorkflowId};
use vos_wire::keys::{self, Transform};
use vos_wire::package::{EPOCH_MS, SLOT_MS};
use vos_wire::package::{Opened, Package};
use vos_wire::records::{Workflow, WorkflowState, stored, unstored};
use vos_wire::result::{Outcome, Outgoing, PAGE, Step, WorkResult, digest, split_output};
use vos_wire::{Decode, Encode, defaults};

use crate::common::{
    AGENT, ALICE, Actors, BOB, CALLER, COUNTER, LEDGER, MINTER, Node, SHOP, done, install,
};

/// A batch time well past JAM's common era; the sessions start at it.
const T0: u64 = 1_760_000_000_000;

/// The agent the shop's workflows ask.
const RISK: AgentId = AgentId(9);

/// A package as it ran.
struct Ran {
    result: WorkResult,
    /// The refine's gas on JAM, and the simulation's.
    jam_gas: u64,
    simulated_gas: u64,
    /// The pages it imported and exported.
    imported: usize,
    exported: usize,
    /// The keys its witness opens, and the rows of its scanned ranges.
    witnessed: usize,
    scanned: usize,
    /// The batch's inputs, its budget, and the package's own work as the
    /// builder estimated it.
    inputs: usize,
    budget: u64,
    own: u64,
}

/// A VOS node, and beside it the agent's builder and its chain.
struct Paired {
    vos: Node,
    runner: Runner,
    builder: Builder,
    chain: Emulated,
    /// Every client's requests, numbered in its session started at `T0`.
    sequences: BTreeMap<Principal, u64>,
    /// Other agents' messages, numbered in their pairs.
    pairs: BTreeMap<AgentId, u64>,
}

impl Paired {
    /// The pair on `backend`, with `programs` the node's and the agent's
    /// preimages, the builder's work packages each of `refine_gas`.
    fn new(backend: PvmBackend, programs: &[&[u8]], refine_gas: u64) -> Self {
        let mut vos = Node::on(backend);
        for program in programs {
            vos.add(program);
        }
        let runner = Runner {
            program: vos.program(),
            service: u64::from(AGENT.0),
            preimages: vos.preimages(),
        };
        Self {
            vos,
            runner,
            builder: Builder::new(Store::temporary().unwrap(), refine_gas).unwrap(),
            chain: Emulated::default(),
            sequences: BTreeMap::new(),
            pairs: BTreeMap::new(),
        }
    }

    /// `caller`'s next request, in its session started at `T0`.
    fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        let sequence = self.sequences.entry(caller).or_insert(0);
        *sequence += 1;
        let key = match caller {
            Principal::Client(key) => key,
            _ => [0; 32],
        };
        Input::Request(Request {
            session: Session {
                key,
                name: [0; 16],
                t0: T0,
            },
            sequence: *sequence,
            caller,
            instance,
            method,
            arguments: arguments.encode(),
        })
    }

    /// A message from `from`, next in its pair.
    fn message(&mut self, from: AgentId, body: Body) -> Input {
        let sequence = self.pairs.entry(from).or_insert(0);
        *sequence += 1;
        Input::Message(Message {
            from,
            sequence: *sequence,
            body,
        })
    }

    /// `inputs` at `time`, as a JAM package and on the VOS node, which must
    /// agree: the builder's batch, which the work package's refine gas
    /// shapes, runs on both.
    fn batch(&mut self, time: u64, inputs: Vec<Input>) -> Ran {
        let seed = Blake2b.hash(b"seed", &[&time.to_le_bytes()]);
        let root = self.builder.store.root().unwrap();
        assert_eq!(
            self.chain.root().unwrap_or_else(|| empty_root(&Blake2b)),
            root,
            "the chain holds the builder's root"
        );
        let prepared = self
            .builder
            .prepare(&self.runner, self.chain.segments(), inputs, time, seed, &[])
            .expect("a package");
        let work = Work::Batch(prepared.package.batch.clone());
        let batch = &prepared.package.batch;
        let (inputs, budget, own) = (batch.inputs.len(), batch.budget, prepared.own);
        assert_eq!(prepared.package.batch.version, self.vos.version);
        let on_vos = self.vos.refine(&work);
        self.vos.accumulate(&on_vos);
        self.vos.version += 1;
        let (vos_result, vos_pages) = split_output(&on_vos).expect("a VOS output");
        let vos_encoded = vos_result.encode();
        assert_eq!(on_vos[..vos_encoded.len()], vos_encoded[..]);
        assert_eq!(
            prepared.simulation.encoded, vos_encoded,
            "the simulation's work result is the VOS node's"
        );
        assert_eq!(prepared.package.root, root);
        assert!(shows(&prepared.package), "the witness verifies");
        assert!(prepared.gas <= self.builder.refine_gas());
        let imports = self
            .builder
            .imports(&prepared, self.chain.segments().as_ref())
            .expect("the pages in DA");
        let refined = self
            .chain
            .refine(&self.runner, &prepared.package, imports, prepared.gas)
            .expect("the package refines within the gas the builder gives it");
        let output = &refined.output;
        assert_eq!(output.root_before, root);
        assert_eq!(output.root_after, prepared.pending.root);
        assert_eq!((output.time, output.seed), (time, seed));
        let slot = (time - EPOCH_MS) / SLOT_MS + 1;
        let stored = self
            .chain
            .accumulate(&self.runner, &refined, slot)
            .expect("accumulate halts");
        assert_eq!(stored, Some(output.root_after), "accumulate takes the root");
        let landed = self.chain.landed().unwrap();
        assert_eq!(
            landed
                .exports
                .map(|exports| (exports.root, exports.pages, exports.segments)),
            Some((refined.segment_root, output.pages, output.exports))
        );
        let pages = output.pages as usize;
        let simulated = prepared.simulation.gas_used;
        assert!(
            refined.gas_used <= simulated + prepared.own,
            "the package's own work, {} beyond the simulation, within its estimate {}",
            refined.gas_used - simulated.min(refined.gas_used),
            prepared.own
        );
        let witness = prepared.package.witness.clone();
        let imported = prepared.package.imports.len();
        let (result, on_chain) = self
            .builder
            .accept(&prepared, &landed, self.chain.segments().as_ref())
            .expect("the builder takes the result");
        assert_eq!(on_chain, vos_encoded, "the chain's work result is VOS's");
        assert_eq!(result, vos_result);
        assert_eq!(self.builder.store.root().unwrap(), output.root_after);

        let exports = self
            .chain
            .da
            .exports(&refined.segment_root)
            .expect("the exports");
        let encoded = exports[pages..].concat();
        assert_eq!(
            encoded[..vos_encoded.len()],
            vos_encoded[..],
            "the work result, byte for byte"
        );
        assert!(encoded[vos_encoded.len()..].iter().all(|byte| *byte == 0));
        let on_jam: Vec<Hash> = exports[..pages]
            .iter()
            .map(|segment| digest(&segment[..PAGE]))
            .collect();
        let on_vos: Vec<Hash> = vos_pages.iter().map(|lz4| digest(&unpacked(lz4))).collect();
        assert_eq!(on_jam, on_vos, "the pages, by hash");
        self.rows_agree();
        Ran {
            result,
            jam_gas: refined.gas_used,
            simulated_gas: simulated,
            imported,
            exported: pages,
            witnessed: witness.keys.len(),
            scanned: witness.ranges.iter().map(|range| range.rows.len()).sum(),
            inputs,
            budget,
            own,
        }
    }

    /// The builder's rows are the VOS node's, but the dirty and seed rows
    /// only a VOS node's root builder needs, and a page row, which holds
    /// the page on a VOS node and its hash on JAM.
    fn rows_agree(&self) {
        let vos: BTreeMap<Vec<u8>, Vec<u8>> = self
            .vos
            .state
            .iter()
            .filter(|(key, _)| {
                !key.starts_with(&keys::dirty_prefix()) && !key.starts_with(&keys::seed_prefix())
            })
            .map(|(key, value)| match keys::page_entry(key) {
                Some(_) => {
                    let page = unpacked(unstored(value).expect("a stored page"));
                    (key.clone(), stored(&digest(&page)))
                }
                None => (key.clone(), value.clone()),
            })
            .collect();
        assert!(
            vos == self.builder.store.view().rows().unwrap(),
            "the builder's rows are the VOS node's"
        );
    }

    fn record(&self, id: u64) -> Workflow {
        self.vos
            .value(&keys::workflow(WorkflowId(id)))
            .expect("a workflow")
    }
}

/// A page LZ4-compressed, whole.
fn unpacked(lz4: &[u8]) -> Vec<u8> {
    lz4_flex::block::decompress(lz4, PAGE).expect("an LZ4 page")
}

/// Every step ran to `Done`, or was refused.
fn ran_or_refused(result: &WorkResult) {
    for step in &result.steps {
        if let Step::Ran(run) = step {
            assert!(
                matches!(run.outcome, vos_wire::result::Outcome::Done(_)),
                "{:?}",
                run.outcome
            );
        }
    }
}

/// The installs of the counter, the ledger with its programs and the
/// caller, and Alice a minter.
fn installs(paired: &mut Paired, actors: &Actors) -> Vec<Input> {
    let counter = ProgramHash::of(&actors.counter);
    let caller = ProgramHash::of(&actors.caller);
    vec![
        install(COUNTER, counter),
        actors.install_ledger(&mut paired.vos),
        install(CALLER, caller),
        Input::Admin(Admin::SetRole(vos_wire::ingress::Grant {
            principal: ALICE,
            role: Some(MINTER),
        })),
    ]
}

fn programs(actors: &Actors) -> Vec<&[u8]> {
    vec![
        &actors.counter,
        &actors.ledger,
        &actors.caller,
        &actors.checksum,
    ]
}

/// A pair with the test actors and the shop, its workflows in its
/// program, installed, and the shop's upgrade among its preimages: and the
/// shop's program.
fn with_shop(backend: PvmBackend, actors: &Actors) -> (Paired, Vec<u8>) {
    let (shop, lean) = (actor("shop"), actor("lean"));
    let mut all = programs(actors);
    all.extend([shop.as_slice(), lean.as_slice()]);
    let mut paired = Paired::new(backend, &all, POLKAJAM_REFINE_GAS);
    let mut first = installs(&mut paired, actors);
    first.push(Input::Admin(Admin::Install {
        instance: SHOP,
        derivation: vos_testkit::programs::bare(ProgramHash::of(&shop)),
        roles: vec![],
    }));
    ran_or_refused(&paired.batch(T0, first).result);
    (paired, shop)
}

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

    // A hashed table, a committed map and an ordered table, filled.
    let count = 300u64;
    let entries: Vec<(u64, Option<u64>)> = (0..count).map(|key| (key * 7, Some(key))).collect();
    let accounts: Vec<(u64, u64)> = (0..count).map(|id| (id * 11, id + 1)).collect();
    let inputs = vec![
        paired.request(
            ALICE,
            COUNTER,
            method(COUNTER, "fill"),
            (count as u32, 8u32),
        ),
        paired.request(ALICE, COUNTER, method(COUNTER, "set_entries"), entries),
        paired.request(ALICE, LEDGER, method(LEDGER, "mint_all"), accounts),
    ];
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
    let fill = paired.request(ALICE, COUNTER, ops, phases(vec![(3, 0, 1_000)]));
    paired.batch(T0 + 1_000, vec![fill]);
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
        paired
            .chain
            .refine(&paired.runner, package, imports, POLKAJAM_REFINE_GAS)
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
        paired.builder.imports(&prepared, &empty),
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
    let imports = paired
        .builder
        .imports(&prepared, &paired.chain.da)
        .expect("the pages in DA");
    let refined = refines(&mut paired, &prepared.package, imports).expect("it refines");
    let before = (paired.chain.root(), paired.builder.store.root().unwrap());
    let skew = defaults::SESSION_SKEW_MS;
    let late = (time + skew - EPOCH_MS) / SLOT_MS + 2;
    let early = (time - skew - EPOCH_MS) / SLOT_MS - 2;
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
    let slot = (time - EPOCH_MS) / SLOT_MS;
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

/// A witness's keys, each opened.
type WitnessKeys = Vec<(Vec<u8>, Opened)>;

/// Whether `package`'s witness verifies against its root, natively: its
/// keys under its multiproof, and each range complete.
fn shows(package: &Package) -> bool {
    use vos_tree::value_hash;
    let witness = &package.witness;
    let claims: Vec<(&[u8], Option<Hash>)> = witness
        .keys
        .iter()
        .map(|(key, opened)| {
            let claim = match opened {
                Opened::Absent => None,
                Opened::Value { salt, value } => Some(value_hash(&Blake2b, salt, value)),
                Opened::Written(hash) => Some(*hash),
            };
            (key.as_slice(), claim)
        })
        .collect();
    let keys = witness
        .proof
        .verify(&Blake2b, &package.root, &claims)
        .is_ok();
    keys && witness.ranges.iter().all(|range| {
        let rows: Vec<(&[u8], Hash)> = range
            .rows
            .iter()
            .map(|row| {
                (
                    row.key.as_slice(),
                    value_hash(&Blake2b, &row.salt, &row.value),
                )
            })
            .collect();
        range
            .proof
            .verify(
                &Blake2b,
                &package.root,
                &range.from,
                range.to.as_deref(),
                &rows,
            )
            .is_ok()
    })
}

/// A builder over its own store, beside the test actors and the shop, and
/// an emulated chain it submits to.
struct Driven {
    actors: Actors,
    shop: Vec<u8>,
    runner: Runner,
    builder: Builder,
    chain: Emulated,
    /// Alice's requests, in her session started at `T0`.
    sequence: u64,
    time: u64,
}

impl Driven {
    /// A builder whose packages each have `refine_gas`, over `store`, and
    /// the actors and the shop installed through it.
    fn new(store: Store, refine_gas: u64) -> Self {
        let actors = Actors::load();
        let (paired, shop) = with_shop(PvmBackend::Default, &actors);
        let mut driven = Self {
            runner: paired.runner,
            builder: Builder::new(store, refine_gas).unwrap(),
            chain: Emulated::default(),
            actors,
            shop,
            sequence: 0,
            time: T0,
        };
        let installs = driven.installs();
        driven.run(installs);
        driven
    }

    fn installs(&mut self) -> Vec<Input> {
        let hash = ProgramHash::of;
        vec![
            install(COUNTER, hash(&self.actors.counter)),
            Input::Admin(Admin::Install {
                instance: SHOP,
                derivation: vos_testkit::programs::bare(hash(&self.shop)),
                roles: vec![],
            }),
        ]
    }

    /// Alice's next request.
    fn request<A: Encode>(
        &mut self,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        self.sequence += 1;
        Input::Request(Request {
            session: Session {
                key: [1; 32],
                name: [0; 16],
                t0: T0,
            },
            sequence: self.sequence,
            caller: ALICE,
            instance,
            method,
            arguments: arguments.encode(),
        })
    }

    /// `inputs` run through the builder's loop, each attempt a second after
    /// the last: the work result.
    fn run(&mut self, inputs: Vec<Input>) -> WorkResult {
        self.try_run(inputs).expect("the package lands").result
    }

    fn try_run(&mut self, inputs: Vec<Input>) -> Result<Taken, Error> {
        let time = &mut self.time;
        let mut clock = || {
            *time += 1_000;
            (*time, Blake2b.hash(b"seed", &[&time.to_le_bytes()]))
        };
        let taken = self
            .builder
            .run(&mut self.chain, &self.runner, &inputs, &mut clock, &[])?;
        assert_eq!(self.chain.root(), Some(self.builder.store.root().unwrap()));
        assert_eq!(taken.encoded, taken.prepared.simulation.encoded);
        Ok(taken)
    }
}

/// A package the chain refused, accumulated past its time or refined out
/// of gas, is made again at a new time, and lands.
#[test]
fn the_builder_makes_a_refused_package_again() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let increment = driven.actors.method(COUNTER, "increment");
    driven.chain.faults = vec![Fault::Late, Fault::Starved];
    let request = driven.request(COUNTER, increment, 5u64);
    let taken = driven.try_run(vec![request.clone()]).expect("it lands");
    assert_eq!(done::<u64>(&taken.result.steps[0]), 5);
    let fates: Vec<Fate> = taken
        .attempts
        .iter()
        .map(|attempt| attempt.fate.clone())
        .collect();
    assert_eq!(fates, [Fate::Refused, Fate::Refused, Fate::Landed]);
    assert!(taken.attempts[1].submitted.contains("refine stopped"));
    // Refused as often as the builder tries, it stops.
    driven.chain.faults = vec![Fault::Late; 4];
    let again = driven.request(COUNTER, increment, 1u64);
    let Err(Error::Attempts(attempts)) = driven.try_run(vec![again]) else {
        panic!("it lands");
    };
    assert_eq!(attempts.len(), 4);
    assert!(attempts.iter().all(|attempt| attempt.fate == Fate::Refused));
}

/// A batch's budget is what a work package's refine gas leaves past the
/// margin and the bound on its own work: a package whose own work passes
/// the bound has it lowered, the refine fitting its gas all the same. A
/// chain whose refine gas leaves a batch less than the least a VOS node
/// refines with is refused, and a batch holds at most as many inputs as a
/// VOS node's.
#[test]
fn the_builder_fits_its_budget_to_a_packages_gas() {
    assert_eq!(builder::budget(POLKAJAM_REFINE_GAS), 900_000_000);
    let below = Builder::new(Store::temporary().unwrap(), 7 * POLKAJAM_REFINE_GAS / 10);
    let least = defaults::min_refine_gas(builder::MAX_INPUTS);
    assert!(
        matches!(below, Err(Error::RefineGas { least: refused, .. }) if refused == least),
        "refused below {least}"
    );
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let fill = driven.actors.method(COUNTER, "fill");
    let fills = (0..2)
        .map(|_| driven.request(COUNTER, fill, (300u32, 8u32)))
        .collect();
    let taken = driven.try_run(fills).expect("it lands");
    let prepared = &taken.prepared;
    let budget = prepared.package.batch.budget;
    let start = prepared.gas - budget - prepared.own;
    assert!(
        prepared.own + start > builder::OWN_BOUND,
        "{} of own work",
        prepared.own
    );
    assert_eq!(
        budget,
        POLKAJAM_REFINE_GAS - POLKAJAM_REFINE_GAS / 1000 * builder::MARGIN - prepared.own - start
    );
    assert!(prepared.gas <= POLKAJAM_REFINE_GAS);
    assert_eq!(
        prepared.simulations, 2,
        "simulated again at the lowered budget"
    );
    assert!(
        taken
            .result
            .steps
            .iter()
            .all(|step| done::<u32>(step) == 300)
    );
    // A batch holds at most a VOS node's inputs; the later ones wait.
    let ack = Input::Ack {
        to: AgentId(5),
        sequence: 1,
    };
    let acks = vec![ack; builder::MAX_INPUTS + 4];
    let segments = driven.chain.segments();
    let time = driven.time + 1_000;
    let prepared = driven
        .builder
        .prepare(&driven.runner, segments, acks, time, [1; 32], &[])
        .expect("a package");
    assert_eq!(prepared.package.batch.inputs.len(), builder::MAX_INPUTS);
}

/// A workflow holding nearly as many pages as a snapshot may, at the
/// largest limit a workflow may declare, runs to its end at the builder's
/// budget, on JAM as on VOS: its last step restores every page and drops
/// every page's row, and its package's own work stays within the bound the
/// builder asserts for it. Requests beside that step, each putting a
/// thousand rows, would leave the batch less than its keep: the batch
/// loses them rather than its budget its floor, and they wait for later
/// packages.
#[test]
fn a_workflow_at_its_page_cap_runs_to_its_end_at_the_builders_budget() {
    let actors = Actors::load();
    let (mut paired, shop) = with_shop(PvmBackend::Default, &actors);
    // Two chunks of whole pages, each a few bytes short of whole pages,
    // which with the workflow's stack and vectors leave it a few pages
    // under the cap.
    let first = cap::HELD_PAGES / 2;
    let second = cap::HELD_PAGES - first - 12;
    let sizes: Vec<u32> = [first, second]
        .map(|pages| (pages * PAGE - 256) as u32)
        .to_vec();
    let total: u64 = sizes.iter().map(|&size| u64::from(size)).sum();
    let start = paired.request(ALICE, SHOP, method(&shop, "fill"), (0u32, sizes));
    let mut time = T0 + 1_000;
    paired.batch(time, vec![start]);
    assert_eq!(paired.record(0).gas, defaults::MAX_HANDLER_GAS);
    // Its steps until it holds every chunk, asleep before its last.
    let mut held = 0;
    while held < cap::HELD_PAGES - 16 {
        let state = paired.record(0).state;
        assert!(
            matches!(
                state,
                WorkflowState::Sleeping { .. } | WorkflowState::Preempted(_)
            ),
            "{state:?}"
        );
        time += 1_000;
        let sweep = paired.vos.sweep(time);
        ran_or_refused(&paired.batch(time, vec![sweep]).result);
        held = paired
            .record(0)
            .snapshot
            .map_or(0, |snapshot| snapshot.pages.len());
    }
    assert!(held <= cap::HELD_PAGES, "{held} pages held");
    // Its last step, beside two requests putting a thousand rows each.
    let ops = actors.method(COUNTER, "ops");
    let requests: Vec<Input> = [0u32, 1_000]
        .map(|start| {
            let puts = vec![(3u8, start, 1_000u32)];
            paired.request(ALICE, COUNTER, ops, (puts, COUNTER.0, 0u32))
        })
        .to_vec();
    time += 1_000;
    let sweep = paired.vos.sweep(time);
    let ending = paired.batch(time, [vec![sweep], requests.clone()].concat());
    ran_or_refused(&ending.result);
    assert_eq!(ending.inputs, 1, "the requests wait");
    assert!(ending.budget >= defaults::min_refine_gas(builder::MAX_INPUTS));
    assert_eq!(
        paired.record(0).state,
        WorkflowState::Ended(Outcome::Done(total.encode()))
    );
    let held = held as u64;
    let bound = gas::ENDING + held * (gas::PAGE_READ + gas::PAGE_DROP);
    assert!(
        ending.own <= bound,
        "the ending's own work {} within {bound}",
        ending.own
    );
    println!(
        "JAM: a workflow's end, {held} pages restored and dropped: own work {}, its budget {}",
        ending.own, ending.budget
    );
    // Later packages take the requests, as many each as keep the floor.
    let mut waiting = requests;
    while !waiting.is_empty() {
        time += 1_000;
        let next = paired.batch(time, waiting.clone());
        assert!(next.inputs >= 1);
        assert!(next.result.steps.iter().all(|step| done::<u64>(step) == 0));
        waiting.drain(..next.inputs);
    }
}

/// Every workflow whose pages DA no longer holds is left out of the sweep
/// before the batch is simulated: however many there are, the package
/// takes at most two simulations, and lands with the rest of the batch,
/// the workflows due still.
#[test]
fn workflows_whose_pages_da_lacks_are_left_out_at_once() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let nap = method(&driven.shop, "nap");
    let starts = (0..3).map(|_| driven.request(SHOP, nap, 500u64)).collect();
    driven.run(starts);
    let naps = [WorkflowId(0), WorkflowId(1), WorkflowId(2)];
    let asleep = |driven: &Driven, id| {
        let workflow = driven.builder.workflow(&ALICE, id).unwrap().unwrap();
        assert!(!workflow.snapshot.unwrap().pages.is_empty(), "its pages");
        matches!(workflow.state, WorkflowState::Sleeping { .. })
    };
    assert!(naps.iter().all(|&id| asleep(&driven, id)));
    // DA forgets every segment exported so far.
    driven.chain.da = vos_jam::Da::default();
    let time = driven.time + 1_000;
    let sweep = driven
        .builder
        .sweep(time)
        .unwrap()
        .expect("the naps are due");
    let increment = driven.actors.method(COUNTER, "increment");
    let request = driven.request(COUNTER, increment, 4u64);
    let taken = driven.try_run(vec![sweep, request]).expect("it lands");
    assert_eq!(taken.prepared.skipped, naps);
    assert!(
        taken.prepared.simulations <= 2,
        "{} simulations",
        taken.prepared.simulations
    );
    assert_eq!(
        taken.prepared.package.batch.inputs.len(),
        1,
        "the sweep left out"
    );
    assert_eq!(done::<u64>(&taken.result.steps[0]), 4);
    assert!(naps.iter().all(|&id| asleep(&driven, id)), "still due");
}

/// A package another builder's landed before: the builder takes that one
/// from its exports, then makes its own again on it. One that cannot be
/// reached from the store stops the builder, its store left as it was.
#[test]
fn the_builder_takes_a_package_that_landed_first() {
    let mut first = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let mut second = Builder::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    let landed = first.chain.landed().unwrap();
    second
        .resync(&first.chain, &landed)
        .expect("one package behind");
    assert_eq!(second.store.root().unwrap(), landed.root);
    // The second lands a package of Bob's.
    let increment = first.actors.method(COUNTER, "increment");
    let bob = Input::Request(Request {
        session: Session {
            key: [2; 32],
            name: [0; 16],
            t0: T0,
        },
        sequence: 1,
        caller: BOB,
        instance: COUNTER,
        method: increment,
        arguments: 3u64.encode(),
    });
    let mut time = first.time + 1_000;
    let mut clock = || {
        time += 1_000;
        (time, [9; 32])
    };
    second
        .run(&mut first.chain, &first.runner, &[bob], &mut clock, &[])
        .expect("the second's package lands");
    first.time = time;
    // The first, a package behind, takes the second's, then lands its own.
    let alice = first.request(COUNTER, increment, 4u64);
    let taken = first.try_run(vec![alice]).expect("it lands");
    assert_eq!(done::<u64>(&taken.result.steps[0]), 7, "on Bob's increment");
    let fates: Vec<Fate> = taken
        .attempts
        .iter()
        .map(|attempt| attempt.fate.clone())
        .collect();
    assert_eq!(fates, [Fate::Overtaken, Fate::Landed]);
    // Two packages behind, the second cannot reach the chain's root.
    let third = first.request(COUNTER, increment, 1u64);
    first.run(vec![third]);
    let before = second.store.root().unwrap();
    let landed = first.chain.landed().unwrap();
    assert_eq!(second.resync(&first.chain, &landed), Err(Error::Diverged));
    assert_eq!(second.store.root().unwrap(), before);
}

/// A batch whose pages pass a work package's exports loses its later
/// inputs, which a later package takes; a package's refine fits its gas.
#[test]
fn the_builder_fits_a_batch_to_a_packages_segments() {
    let mut driven = Driven::new(Store::temporary().unwrap(), 8_000_000_000);
    let compute = method(&driven.shop, "compute");
    let starts: Vec<Input> = (0..7)
        .map(|_| driven.request(SHOP, compute, (262_144u32, 1u32)))
        .collect();
    let (time, seed) = (driven.time + 1_000, [1; 32]);
    let prepared = driven
        .builder
        .prepare(
            &driven.runner,
            driven.chain.segments(),
            starts.clone(),
            time,
            seed,
            &[],
        )
        .expect("a package");
    let exports = prepared.exports() as usize;
    let inputs = prepared.package.batch.inputs.len();
    assert!(inputs < starts.len(), "{inputs} of the starts");
    assert!(
        exports <= vos_wire::package::MAX_SEGMENTS,
        "{exports} exports"
    );
    assert!(
        exports > vos_wire::package::MAX_SEGMENTS / 3,
        "{exports} exports"
    );
    let refined = driven
        .chain
        .refine(&driven.runner, &prepared.package, vec![], prepared.gas)
        .expect("the package refines within its gas");
    assert!(refined.gas_used <= prepared.gas);
    println!(
        "JAM: {inputs} of 7 computations in a package: {exports} exports, refine {} of {} gas",
        refined.gas_used, prepared.gas
    );
}

/// The builder's store outlives it: reopened, it holds the same root and
/// where the pages it took were exported, so a workflow it suspended
/// resumes from their imports. The packages it lands solicit what it
/// names.
#[test]
fn the_builders_store_outlives_it() {
    let scratch =
        Scratch(std::env::temp_dir().join(format!("vos-jam-outlives-{}", std::process::id())));
    let path = &scratch.0;
    let _ = std::fs::remove_dir_all(path);
    let mut driven = Driven::new(Store::open(path).unwrap(), POLKAJAM_REFINE_GAS);
    let nap = method(&driven.shop, "nap");
    let start = driven.request(SHOP, nap, 500u64);
    driven.run(vec![start]);
    let root = driven.builder.store.root().unwrap();
    let program = ProgramHash::of(&driven.actors.counter);
    let len = driven.actors.counter.len() as u32;
    // The builder gone, its store reopened: the old one is dropped first,
    // which releases its lock on the directory, a temporary store standing
    // in meanwhile.
    driven.builder = Builder::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    driven.builder = Builder::new(Store::open(path).unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    assert_eq!(driven.builder.store.root().unwrap(), root);
    let time = driven.time + 1_000;
    let sweep = driven.builder.sweep(time).unwrap().expect("the nap is due");
    let mut clock = || (time, [7; 32]);
    let Taken {
        prepared, result, ..
    } = driven
        .builder
        .run(
            &mut driven.chain,
            &driven.runner,
            &[sweep],
            &mut clock,
            &[(program, len)],
        )
        .expect("the nap resumes");
    assert!(!prepared.package.imports.is_empty(), "its pages imported");
    let workflow = driven
        .builder
        .workflow(&ALICE, WorkflowId(0))
        .unwrap()
        .expect("Alice's workflow");
    assert!(
        matches!(workflow.state, WorkflowState::Ended(_)),
        "{result:?}"
    );
    assert_eq!(driven.builder.workflow(&BOB, WorkflowId(0)).unwrap(), None);
    assert!(
        driven
            .chain
            .solicited
            .contains(&(program.0, u64::from(len)))
    );
}

/// A directory removed when dropped, so a test that panics leaves none.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A workflow keeps the program it started on through an upgrade on JAM
/// too: its program is a preimage the builder never forgets, so the
/// workflow resumes on it and ends there, while a start since runs the
/// upgrade.
#[test]
fn a_workflow_resumes_on_its_program_through_an_upgrade_on_jam() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let hash = ProgramHash::of;
    let (shop, lean) = (hash(&driven.shop), hash(&actor("lean")));
    let nap = method(&driven.shop, "nap");
    let start = driven.request(SHOP, nap, 2_500u64);
    driven.run(vec![start]);
    driven.run(vec![Input::Admin(Admin::Install {
        instance: SHOP,
        derivation: vos_testkit::programs::bare(lean),
        roles: vec![],
    })]);
    let record = |driven: &Driven, id: u64| {
        let row = driven
            .builder
            .store
            .view()
            .get(&keys::workflow(WorkflowId(id)));
        Workflow::decode(unstored(&row.unwrap().unwrap()).unwrap())
            .unwrap()
            .0
    };
    for _ in 0..10 {
        if matches!(record(&driven, 0).state, WorkflowState::Ended(_)) {
            break;
        }
        if let Some(sweep) = driven.builder.sweep(driven.time + 1_000).unwrap() {
            driven.run(vec![sweep]);
        } else {
            driven.time += 1_000;
        }
    }
    let napped = record(&driven, 0);
    assert_eq!(napped.program, shop);
    assert!(
        matches!(napped.state, WorkflowState::Ended(Outcome::Done(_))),
        "{:?}",
        napped.state
    );
    let start = driven.request(SHOP, nap, 1u64);
    driven.run(vec![start]);
    assert_eq!(record(&driven, 1).program, lean);
}
