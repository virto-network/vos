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
use vos_testkit::programs::{derived, kernel, method, package};
use vos_testkit::{Testkit, run_kernel};
use vos_tree::{BatchProof, Blake2b, Leaf, MemStore};
use vos_wire::abi::cap::{self, Target};
use vos_wire::abi::{AttestError, Failure, Kind, price};
use vos_wire::batch::{Body, Input, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, ProgramHash, RequestId, Session, WorkflowId};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::records::{PendingRead, Workflow, WorkflowState, unstored, unversioned};
use vos_wire::result::{Attest, InputRef, Outcome, Run, Step, WorkResult};
use vos_wire::served::{Served, representative_row, space_root};
use vos_wire::vos_anchor::{MIN_LENGTH_MS, RootKind, RootRead, VenueId};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, defaults};

use crate::common::{AGENT, ALICE, Node, agrees, install_in, ran};

mod cuts;
mod pricing;
mod serving;

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
/// The space's representative.
const REPRESENTATIVE: AgentId = AgentId(0x0900_0000);

/// The reader in a node and the model, in an agent of `SPACE` or of none,
/// and what drives them.
struct Reads {
    node: Node,
    kit: Testkit,
    /// Alice's requests so far, in her session opened at `T0`.
    sequence: u64,
    /// The representative's messages to the agent so far.
    closes: u64,
    /// The last batch's time.
    time: u64,
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
        let (kit, _) = install_in(
            &mut node,
            (space, CLOCK),
            target,
            READER,
            &package("reader"),
            &derived,
        );
        Self {
            node,
            kit,
            sequence: 0,
            closes: 0,
            time: 0,
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
        self.time = time;
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
                Due::Session(_) | Due::Binding(_) => None,
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
                    Input::Report { to, window, root } => self.kit.report(*to, *window, *root),
                    Input::Message(message) => self.kit.message(message.from, &message.body),
                    Input::Close {
                        window,
                        rep_root,
                        paths,
                    } => self.kit.close(*window, *rep_root, paths.clone()),
                    Input::Proven {
                        window, id, proof, ..
                    } => self.kit.proven(*window, *id, *proof),
                    other => panic!("not modelled: {other:?}"),
                },
                Step::Swept { .. } | Step::Refused { .. } => {
                    inputs.next();
                    self.kit.pass();
                    continue;
                }
            };
            agrees(index, ran(step), &expected);
        }
        self.sync_cuts();
        result
    }

    /// The rows the node's apply writes and deletes with a cut, which the
    /// model leaves to it: the cuts, the latest recording's windows and the
    /// closes it keeps, as the node holds them after a batch.
    fn sync_cuts(&mut self) {
        let ours = |key: &Vec<u8>| {
            key.starts_with(&keys::closed_prefix())
                || key.starts_with(&keys::cuts())
                || *key == keys::cut_mark()
        };
        let held: Vec<Vec<u8>> = self
            .kit
            .rows()
            .into_iter()
            .map(|(key, _)| key)
            .filter(&ours)
            .collect();
        for key in held {
            self.kit.delete_row(&key);
        }
        let rows: Vec<(Vec<u8>, Vec<u8>)> = self
            .node
            .state
            .iter()
            .filter(|(key, _)| ours(key))
            .map(|(key, value)| (key.clone(), unstored(value).unwrap().to_vec()))
            .collect();
        for (key, value) in rows {
            self.kit.set_row(key, value);
        }
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
    /// tree's root in a representative's tree of that root alone; the
    /// window's cut, the agent's report of the root and the
    /// representative's `Closed` of the window applied first, unless the
    /// agent holds one.
    fn served(&mut self, window: u64, read: &PendingRead) -> Served {
        let rows = self.committed();
        let (store, agent_root) = tree(
            &SEED,
            rows.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        let (rep_root, rep_salt, space_path) =
            representative(&[(AGENT, window, agent_root)], (AGENT, window));
        if self.node.get(&keys::closed(window)).is_none() {
            // The window's cut, as apply records it once a result crosses
            // its boundary: a test serving within the window stands for it.
            if self.node.get(&keys::cut(window)).is_none() {
                let version = self.node.value::<u64>(&keys::version()).unwrap_or(0);
                let cut = vos_wire::records::stored(&version.encode());
                self.node.state.insert(keys::cut(window), cut);
                self.kit.set_row(keys::cut(window), version.encode());
            }
            self.close(window, agent_root, (rep_root, rep_salt, space_path.clone()));
        }
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

    /// The agent's report of `agent_root` at window `window`'s cut, and the
    /// representative's `Closed` of it, `(rep_root, rep_salt, space_path)`,
    /// at the last batch's time.
    fn close(&mut self, window: u64, agent_root: [u8; 32], close: ([u8; 32], [u8; 16], Vec<u8>)) {
        let (rep_root, rep_salt, space_path) = close;
        self.closes += 1;
        let report = Input::Report {
            to: REPRESENTATIVE,
            window,
            root: agent_root,
        };
        let closed = Input::Message(Message {
            from: REPRESENTATIVE,
            sequence: self.closes,
            body: Body::Closed {
                window,
                rep_root,
                rep_salt,
                space_path,
            },
        });
        let result = self.batch(self.time, vec![report, closed]);
        assert_eq!(result.steps.len(), 2, "the close applied");
        assert!(self.node.get(&keys::closed(window)).is_some(), "closed");
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
