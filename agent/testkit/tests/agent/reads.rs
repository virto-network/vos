//! Reads at a window's cut ([`vos_wire::abi::Op::AttestAt`]) on the default
//! agent, step by step against the testkit: a workflow's ask recorded as
//! its window's pending request, its rows served by a `Resume` and run
//! through the `&self` method's kernel, which checks them against the
//! space's root and states it; what the agent refuses at the ask, what it
//! does not serve, a read not served in time; the public arguments' forms;
//! and an at-cut attest counting two against a step's attests.
//!
//! The served rows come from the agent's committed rows as the node holds
//! them now, under a tree of them salted from a fixed seed, and a
//! representative's tree a test builds: what a cut's build and the space's
//! representative give a node, as the kernel checks it.

use std::collections::BTreeMap;

use vos_pvm_compiler::Derived;
use vos_testkit::programs::{derivation, derived, method, package};
use vos_testkit::{Testkit, run_kernel};
use vos_tree::{BatchProof, Blake2b, Leaf, MemStore};
use vos_wire::abi::cap::{self, Target};
use vos_wire::abi::{AttestError, Failure, Kind, price};
use vos_wire::batch::{Admin, Input, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, ProgramHash, RequestId, Session, WorkflowId};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::records::{PendingRead, Workflow, WorkflowState, unstored, unversioned};
use vos_wire::result::{Attest, InputRef, Outcome, Run, Step, WorkResult};
use vos_wire::served::{Served, representative_row, space_root};
use vos_wire::vos_anchor::{MIN_LENGTH_MS, RootKind, RootRead, VenueId};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, defaults};

use crate::common::{AGENT, ALICE, Node, ran};

const READER: InstanceId = InstanceId(5);
const SPACE: SpaceId = SpaceId([0x5a; 32]);
const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: MIN_LENGTH_MS,
};
/// A time in window 10.
const T0: u64 = 10 * MIN_LENGTH_MS + 1_000;
const WINDOW: u64 = 10;
/// The seed the agent's committed rows' leaves are salted from here.
const SEED: [u8; 32] = [3; 32];
/// The seed of the representative's tree a test builds.
const REP_SEED: [u8; 32] = [4; 32];
const VENUE: VenueId = VenueId([0x7e; 32]);

/// The reader in a node and the model, in an agent of `SPACE` or of none,
/// and what drives them.
struct Reads {
    node: Node,
    kit: Testkit,
    /// Alice's requests so far, in her session opened at `T0`.
    sequence: u64,
    derived: Derived,
}

impl Reads {
    /// The reader installed for `target` in an agent of `space`.
    fn new(target: Target, space: SpaceId) -> Self {
        let derived = derived("reader");
        let mut node = match target {
            Target::Vos => Node::new(),
            Target::Jam => Node::jam(true),
        };
        node.add(&derived.actor);
        for (_, kernel) in &derived.kernels {
            node.add(kernel);
        }
        let install = Input::Admin(Admin::Install {
            instance: READER,
            derivation: derivation(&package("reader"), &derived),
            roles: vec![],
            target,
            space,
            clock: CLOCK,
        });
        node.batch(0, vec![install]);
        let mut kit = Testkit::new(AGENT);
        kit.install_derived_in((space, CLOCK), target, READER, &derived, &[])
            .unwrap();
        kit.version = node.version;
        Self {
            node,
            kit,
            sequence: 0,
            derived,
        }
    }

    /// The reader in an agent of `SPACE` on a VOS node, its entries
    /// `entries` set at `T0`.
    fn with(entries: &[(u64, u64)]) -> Self {
        let mut reads = Self::new(Target::Vos, SPACE);
        let writes: Vec<(u64, Option<u64>)> = entries
            .iter()
            .map(|&(key, value)| (key, Some(value)))
            .collect();
        let set = reads.request("set_entries", writes);
        let result = reads.batch(T0, vec![set]);
        assert!(matches!(ran(&result.steps[0]).outcome, Outcome::Done(_)));
        reads
    }

    fn method(&self, name: &str) -> MethodId {
        method(&self.derived.actor, name)
    }

    /// The kernel of attestable `name`.
    fn kernel(&self, name: &str) -> &[u8] {
        let id = self.method(name);
        self.derived
            .kernels
            .iter()
            .find(|(method, _)| *method == id.0)
            .map(|(_, kernel)| kernel.as_slice())
            .expect("a kernel")
    }

    /// Alice's request of the reader's `name`, next in her session.
    fn request<A: Encode>(&mut self, name: &str, arguments: A) -> Input {
        self.sequence += 1;
        Input::Request(Request {
            session: Session {
                key: [1; 32],
                name: [0; 16],
                t0: T0,
            },
            sequence: self.sequence,
            caller: ALICE,
            instance: READER,
            method: self.method(name),
            arguments: arguments.encode(),
        })
    }

    /// A batch at `time`, refined and accumulated on the node, each step
    /// run on the model too, which must agree.
    fn batch(&mut self, time: u64, inputs: Vec<Input>) -> WorkResult {
        let result = self.node.batch(time, inputs.clone());
        self.kit.batch(time, [0; 32]);
        let listed: BTreeMap<WorkflowId, u64> = inputs
            .iter()
            .filter_map(|input| match input {
                Input::Sweep { due } => Some(due),
                _ => None,
            })
            .flatten()
            .filter_map(|&(at, due)| match due {
                Due::Workflow(workflow) => Some((workflow, at)),
                Due::Session(_) => None,
            })
            .collect();
        let mut inputs = inputs.iter();
        for (index, step) in result.steps.iter().enumerate() {
            let expected = match step {
                Step::Ran(Run {
                    input: InputRef::Due { workflow },
                    ..
                }) => {
                    let at = listed.get(workflow).copied().unwrap_or(time);
                    self.kit.due(at, *workflow)
                }
                Step::Ran(_) => match inputs.next().expect("an input") {
                    Input::Request(request) => self.kit.command(
                        request.caller,
                        request.instance,
                        request.method,
                        &request.arguments,
                    ),
                    Input::Resume {
                        window,
                        request,
                        served,
                    } => self.kit.resume_read(*window, *request, served.clone()),
                    other => panic!("not modelled: {other:?}"),
                },
                Step::Swept { .. } | Step::Refused { .. } => {
                    inputs.next();
                    self.kit.pass();
                    continue;
                }
            };
            let run = ran(step);
            assert_eq!(run.outcome, expected.outcome, "step {index}'s outcome");
            assert_eq!(run.writes, expected.writes, "step {index}'s writes");
            assert_eq!(run.attests, expected.attests, "step {index}'s attests");
            assert_eq!(run.pages, expected.pages, "step {index}'s pages");
            assert_eq!(run.gas_used, expected.gas_used, "step {index}'s gas");
            assert_eq!(run.instances, expected.instances, "step {index}'s gas");
        }
        result
    }

    /// Start the reader's workflow `name` at `time`: its id, the ask run
    /// in the same batch.
    fn start<A: Encode>(&mut self, time: u64, name: &str, arguments: A) -> WorkflowId {
        let start = self.request(name, arguments);
        let result = self.batch(time, vec![start]);
        match ran(&result.steps[0]).outcome {
            Outcome::Started(id) => id,
            ref other => panic!("not started: {other:?}"),
        }
    }

    fn record(&self, id: WorkflowId) -> Workflow {
        self.node.value(&keys::workflow(id)).expect("a workflow")
    }

    /// The request workflow `id` awaits at its await `counter`, of window
    /// `window`, and the rows it reads, as its row holds them.
    fn asked(&self, window: u64, id: WorkflowId, counter: u64) -> (RequestId, PendingRead) {
        let request = RequestId {
            workflow: id,
            awaits: counter,
        };
        let read: PendingRead = self
            .node
            .value(&keys::request(window, request))
            .expect("the pending request");
        (request, read)
    }

    /// The agent's committed rows now, each with its bare value.
    fn committed(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let prefix = keys::committed_all();
        self.node
            .state
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(key, stored)| {
                let (_, value) = unversioned(unstored(stored).unwrap()).unwrap();
                (key.clone(), value.to_vec())
            })
            .collect()
    }

    /// The rows `read` names served at window `window` from the agent's
    /// committed rows now, under the tree of them, with the path of the
    /// tree's root in a representative's tree of that root alone.
    fn served(&self, window: u64, read: &PendingRead) -> Served {
        let rows = self.committed();
        let (store, agent_root) = tree(
            &SEED,
            rows.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        let (rep_root, rep_salt, space_path) =
            representative(&[(AGENT, window, agent_root)], (AGENT, window));
        Served {
            space: SPACE,
            window,
            agent: AGENT,
            instance: read.instance,
            agent_root,
            rep_root,
            rep_salt,
            space_path,
            rows: read
                .rows
                .iter()
                .map(|key| {
                    let held = rows
                        .get(key)
                        .map(|value| (vos_tree::salt(&Blake2b, &SEED, key), value.clone()));
                    (key.clone(), held)
                })
                .collect(),
            rows_proof: BatchProof::generate(&store, &read.rows).unwrap().encode(),
        }
    }

    /// The `Resume` of `request`'s read of window `window`, served.
    fn resume(&self, window: u64, request: RequestId, served: Option<&Served>) -> Input {
        Input::Resume {
            window,
            request,
            served: served.map(Encode::encode),
        }
    }
}

/// A change a test makes to served rows, by its name.
type Change = (&'static str, fn(&mut Served));

/// A tree over `rows`, each leaf salted from `seed`: its store and root.
fn tree(seed: &[u8; 32], rows: Vec<(Vec<u8>, Vec<u8>)>) -> (MemStore, [u8; 32]) {
    let mut store = MemStore::default();
    if rows.is_empty() {
        return (store, vos_tree::empty_root(&Blake2b));
    }
    let leaves: Vec<(Vec<u8>, Option<Leaf>)> = rows
        .into_iter()
        .map(|(key, value)| {
            let leaf = Leaf::salted(&Blake2b, seed, &key, &value);
            (key, Some(leaf))
        })
        .collect();
    let root = vos_tree::update(&Blake2b, &mut store, &leaves).unwrap();
    (store, root)
}

/// A representative's tree over `roots`, each an agent's root at a window:
/// its root, and the salt and path of `of`'s row in it.
fn representative(
    roots: &[(AgentId, u64, [u8; 32])],
    of: (AgentId, u64),
) -> ([u8; 32], [u8; 16], Vec<u8>) {
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = roots
        .iter()
        .map(|&(agent, window, root)| {
            let row = representative_row(agent, RootKind::Space, window);
            (row, root.to_vec())
        })
        .collect();
    rows.sort();
    let (store, root) = tree(&REP_SEED, rows);
    let row = representative_row(of.0, RootKind::Space, of.1);
    let salt = vos_tree::salt(&Blake2b, &REP_SEED, &row);
    let path = BatchProof::generate(&store, &[row]).unwrap().encode();
    (root, salt, path)
}

/// The full keys of the reader's entries under `keys`, sorted, as a read
/// names them.
fn entry_rows(keys: &[u64]) -> Vec<Vec<u8>> {
    let map = vos_wire::ids::MapId {
        instance: READER,
        tag: vos_testkit::programs::table_tag("entries"),
        transform: Transform::Hashed,
    };
    let mut rows: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| keys::committed(&map, &Transform::Hashed.apply(&key.to_be_bytes())))
        .collect();
    rows.sort();
    rows
}

/// A workflow's outcome once ended.
fn ended(record: &Workflow) -> &Outcome {
    match &record.state {
        WorkflowState::Ended(outcome) => outcome,
        other => panic!("not ended: {other:?}"),
    }
}

/// The outcome of a workflow that returned the read's error.
fn failed_with(error: AttestError) -> Outcome {
    Outcome::Failed {
        code: Failure::Handler,
        detail: error.encode(),
    }
}

/// The run of the step a `Resume` of `request` made.
fn resumed(result: &WorkResult, request: RequestId) -> &Run {
    result
        .steps
        .iter()
        .find_map(|step| match step {
            Step::Ran(run) if run.input == (InputRef::Resume { request }) => Some(run),
            _ => None,
        })
        .expect("the resume's step")
}

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
            program: ProgramHash::of(reads.kernel("sum_entries")),
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
/// agent's root another, the space path tampered, the representative's
/// root another, a representative's tree without the agent's row, and the
/// leaf's salt another. Each traps, and the workflow sees the attest fail;
/// the rows as they are attest.
#[test]
fn a_tampered_witness_traps_the_kernel() {
    let mut reads = Reads::with(&[(1, 10), (2, 20)]);
    let tampers: [Change; 7] = [
        ("a row's value", |served| {
            served.rows[0].1.as_mut().unwrap().1[0] ^= 1;
        }),
        ("the rows' proof", |served| {
            let last = served.rows_proof.len() - 1;
            served.rows_proof[last] ^= 1;
        }),
        ("the agent's root", |served| served.agent_root[0] ^= 1),
        ("the space path", |served| {
            let last = served.space_path.len() - 1;
            served.space_path[last] ^= 1;
        }),
        ("the representative's root", |served| {
            served.rep_root[0] ^= 1
        }),
        ("the representative's row", |served| {
            let other = AgentId(AGENT.0 + 1);
            let (root, _, path) = representative(
                &[(other, served.window, served.agent_root)],
                (served.agent, served.window),
            );
            served.rep_root = root;
            served.space_path = path;
        }),
        ("the leaf's salt", |served| served.rep_salt[0] ^= 1),
    ];
    for (at, (name, tamper)) in (T0 + 10..).step_by(20).zip(tampers) {
        let id = reads.start(at, "sum_at_cut", vec![1u64, 2]);
        let (request, read) = reads.asked(WINDOW, id, 0);
        let mut served = reads.served(WINDOW, &read);
        tamper(&mut served);
        let resume = reads.resume(WINDOW, request, Some(&served));
        let result = reads.batch(at + 10, vec![resume]);
        assert!(resumed(&result, request).attests.is_empty(), "{name}");
        assert_eq!(
            ended(&reads.record(id)),
            &failed_with(AttestError::Failed),
            "{name}"
        );
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
    let kernel = reads.kernel("sum_entries").to_vec();
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

/// The gas the refine of `inputs` at `time` spends beyond its steps' gas,
/// which holds what they run and are charged: the agent's own work, less
/// what the charges cover of it. The node's state is left as it was.
fn unpaid(node: &Node, time: u64, inputs: Vec<Input>) -> i64 {
    let invocation = node.run_refine(&node.work(time, inputs), crate::common::OUTER_GAS);
    let output = invocation.output_bounded(cap::OUTPUT).unwrap();
    let (result, _) = vos_wire::result::split_output(&output).unwrap();
    let steps: u64 = result.steps.iter().map(|step| ran(step).gas_used).sum();
    invocation.gas_used as i64 - steps as i64
}

/// What the agent spends serving a read of a hundred and fifty rows beyond
/// what its step is charged, against the same read unserved: decoding and
/// checking the rows, copying them into the kernel's input, serving them
/// to it and keeping them in its attest, and its compressions' serving. It
/// leaves a fifth spare of what the agent accounts for them: `SERVED_BYTE`
/// a byte, `PRECOMPILE_SERVING` a compression.
#[test]
fn serving_a_read_pays_for_itself() {
    let entries: Vec<(u64, u64)> = (0..200).map(|key| (key, key)).collect();
    let mut reads = Reads::with(&entries);
    let keys: Vec<u64> = (0..150).collect();
    let id = reads.start(T0 + 10, "sum_at_cut", keys.clone());
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let bytes = served.encode().len();
    let input = [keys.encode(), served.encode()].concat();
    let ran = run_kernel(reads.kernel("sum_entries"), &input, 1 << 32).unwrap();
    let at = |served: Option<&Served>| {
        unpaid(
            &reads.node,
            T0 + 20,
            vec![reads.resume(WINDOW, request, served)],
        )
    };
    let spent = at(Some(&served)) - at(None);
    let accounted =
        defaults::SERVED_BYTE * bytes as u64 + defaults::PRECOMPILE_SERVING * ran.compressions;
    println!(
        "a read of {} rows, {bytes} bytes and {} compressions served: the agent spends {spent} \
         beyond its charges, {:.1} a byte, of {accounted} accounted",
        keys.len(),
        ran.compressions,
        spent as f64 / bytes as f64,
    );
    assert!(
        spent <= (accounted * 4 / 5) as i64,
        "{spent} of {accounted}"
    );
}

/// What the agent spends checking a `Stating` kernel's statement parts,
/// their io-hash, for each block of its return, beyond what its caller is
/// charged: sixteen attests of 8 KiB against sixteen of none. It leaves a
/// fifth of the charge, `IO_HASH_BLOCK` a block, spare.
#[test]
fn checking_statement_parts_pays_for_itself() {
    let mut reads = Reads::with(&[(1, 1)]);
    let len = 8u32 << 10;
    // Neither refine applies: both requests are the session's next.
    let mut at = |len: u32| {
        let input = reads.request("attest_padded", (16u32, len));
        reads.sequence -= 1;
        unpaid(&reads.node, T0 + 10, vec![input])
    };
    let blocks = 16 * i64::from(len) / 128;
    let beyond = (at(len) - at(0)) / blocks;
    let cost = price::IO_HASH_BLOCK as i64 + beyond;
    println!(
        "a statement's parts checked: charged {} a block, costs the agent {cost}",
        price::IO_HASH_BLOCK
    );
    assert!(cost <= (price::IO_HASH_BLOCK * 4 / 5) as i64, "{cost}");
}

/// A read whose kernel spends the step's limit answers its workflow: run
/// out of gas, the step is preempted and the workflow resumes in the next
/// with the attest failed; run to its end leaving the step no gas, the step
/// is preempted with the statement recorded, and the workflow resumes with
/// its output.
#[test]
fn a_read_whose_kernel_spends_the_step_answers_its_workflow() {
    let mut reads = Reads::with(&[(1, 7)]);
    let limit = 2_000_000 - price::ATTEST;
    let kernel = reads.kernel("spin").to_vec();
    let id = reads.start(T0 + 10, "spin_at_cut", (1u64, 0u64));
    let (_, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read).encode();
    let runs = |rounds: u64| {
        let input = [(1u64, rounds).encode(), served.clone()].concat();
        run_kernel(&kernel, &input, limit).is_ok()
    };
    // The most rounds the kernel runs within the step's limit.
    let (mut low, mut high) = (0u64, 1 << 20);
    assert!(runs(low) && !runs(high));
    while high - low > 1 {
        let mid = (low + high) / 2;
        if runs(mid) { low = mid } else { high = mid }
    }
    for (at, (rounds, done)) in (T0 + 20..).step_by(20).zip([(high, false), (low, true)]) {
        let id = reads.start(at, "spin_at_cut", (1u64, rounds));
        let (request, read) = reads.asked(WINDOW, id, 0);
        let served = reads.served(WINDOW, &read);
        let resume = reads.resume(WINDOW, request, Some(&served));
        let result = reads.batch(at + 5, vec![resume]);
        assert_eq!(resumed(&result, request).attests.len(), usize::from(done));
        assert!(
            matches!(reads.record(id).state, WorkflowState::Preempted(_)),
            "{:?}",
            reads.record(id).state
        );
        let sweep = reads.node.sweep(at + 10);
        reads.batch(at + 10, vec![sweep]);
        let ended = ended(&reads.record(id)).clone();
        if done {
            let output = &resumed(&result, request).attests[0].output;
            assert_eq!(ended, Outcome::Done(output.clone()));
        } else {
            assert_eq!(ended, failed_with(AttestError::Failed));
        }
    }
}
