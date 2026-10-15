//! Workflows: started by a request or a call, stepped by the replies,
//! deadlines and timers that resume them, snapshotted between steps, and
//! ended, failed and collected. Every test runs on the interpreter and the
//! recompiler, every step against the testkit's model, and the two
//! backends agree on every byte.

use std::collections::BTreeMap;

use vos_testkit::programs::{actor, method};
use vos_testkit::{Step as KitStep, Testkit, decode};
use vos_wire::abi::{Failure, Op, cap, price};
use vos_wire::batch::{Admin, Answer, Await, Body, Input, Message};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, WorkflowId};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Workflow, WorkflowState, stored};
use vos_wire::result::{InputRef, Outcome, Outgoing, Run, Step, WorkResult, split_output};
use vos_wire::{Encode, defaults};

use crate::common::{ALICE, Actors, COUNTER, LEDGER, Node, SHOP, Sessions, ran};

mod budget;
mod hosts;
mod lifecycle;
mod preemption;
mod sections;

/// The agent the shop's workflows ask, at its counter, instance 1.
const RISK: AgentId = AgentId(9);

/// The shop's limits: `settle`'s, `relay`'s, `press`'s and `grind`'s.
const SETTLE_LIMIT: u64 = 50_000_000;
const RELAY_LIMIT: u64 = 5_000_000;
const PRESS_LIMIT: u64 = 200_000;
const GRIND_LIMIT: u64 = 20_000_000;

/// `settle`'s rounds: nine tenths of its limit in reads of the time, at
/// their price.
fn settle_rounds() -> u32 {
    (9 * SETTLE_LIMIT / 10 / price::OPERATION) as u32
}

/// `relay`'s arguments for `times` rounds: seven tenths of its limit in
/// reads of the time, then an echo whose bytes alone, in and out, cost four
/// tenths more, so each echo's await spends the share.
fn relayed(times: u32) -> (u32, u32, u32) {
    let rounds = (7 * RELAY_LIMIT / 10 / price::OPERATION) as u32;
    let len = (4 * RELAY_LIMIT / 10 / (2 * price::PER_BYTE)) as u32;
    (rounds, len, times)
}

/// A node and the model with the test actors and the shop installed, and
/// what drives them: the client's sessions, other agents' pair sequences,
/// and the batch time.
pub struct Flows {
    actors: Actors,
    programs: BTreeMap<&'static str, Vec<u8>>,
    node: Node,
    kit: Testkit,
    sessions: Sessions,
    pairs: BTreeMap<AgentId, u64>,
    time: u64,
    /// Each batch's budget.
    budget: u64,
}

/// The shop's programs, its workflows in each: its own, one with a heap
/// for its largest steps, one with a heap past what a workflow may write,
/// and one with the default heap, which an upgrade installs.
fn programs() -> BTreeMap<&'static str, Vec<u8>> {
    static PROGRAMS: std::sync::OnceLock<BTreeMap<&'static str, Vec<u8>>> =
        std::sync::OnceLock::new();
    PROGRAMS
        .get_or_init(|| {
            ["shop", "big", "huge", "lean"]
                .into_iter()
                .map(|name| (name, actor(name)))
                .collect()
        })
        .clone()
}

impl Flows {
    pub fn new(node: Node) -> Self {
        let mut flows = Self {
            actors: Actors::load(),
            programs: programs(),
            node,
            kit: Testkit::new(crate::common::AGENT),
            sessions: Sessions::new(),
            pairs: BTreeMap::new(),
            time: 0,
            budget: crate::common::OUTER_GAS,
        };
        flows.actors.install(&mut flows.node, &mut flows.kit);
        let install = flows.install("shop");
        flows.node.batch(0, vec![install]);
        flows.kit.version = flows.node.version;
        flows
    }

    /// The shop's install as its program `program`, in the node, which
    /// stores it, and in the model.
    fn install(&mut self, program: &str) -> Input {
        let shop = &self.programs[program];
        self.kit.install(SHOP, shop, &[], &[]).unwrap();
        Input::Admin(Admin::Install {
            instance: SHOP,
            derivation: vos_testkit::programs::bare(self.node.add(shop)),
            roles: vec![],
        })
    }

    fn method(&self, name: &str) -> MethodId {
        method(&self.programs["shop"], name)
    }

    fn program(&self, name: &str) -> ProgramHash {
        ProgramHash::of(&self.programs[name])
    }

    /// Alice's request starting the shop's workflow `name`.
    pub fn start<A: Encode>(&mut self, name: &str, arguments: A) -> Input {
        self.start_bytes(name, arguments.encode())
    }

    /// [`Flows::start`] with its arguments encoded.
    pub fn start_bytes(&mut self, name: &str, arguments: Vec<u8>) -> Input {
        let method = self.method(name);
        self.sessions.request_bytes(ALICE, SHOP, method, arguments)
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

    /// `from`'s answer to workflow `workflow`'s await `counter`.
    fn reply(&mut self, from: AgentId, workflow: u64, counter: u64, answer: Answer) -> Input {
        let awaiting = Await {
            workflow: WorkflowId(workflow),
            counter,
        };
        self.message(from, Body::Reply { awaiting, answer })
    }

    /// A batch `after` milliseconds past the last, refined and accumulated
    /// on the node, and every step of it run on the model, which must
    /// agree.
    fn batch(&mut self, after: u64, inputs: Vec<Input>) -> WorkResult {
        self.measured(after, inputs).0
    }

    /// The same with batches of the default budget.
    fn at_default_budget(node: Node) -> Self {
        Self {
            budget: defaults::REFINE_GAS,
            ..Self::new(node)
        }
    }

    /// The refine of a batch `after` milliseconds past the last, neither
    /// accumulated nor modelled.
    fn refine(&self, after: u64, inputs: Vec<Input>) -> vos_pvm::refine::Invocation {
        let work = self
            .node
            .budgeted_work(self.time + after, [0; 32], self.budget, inputs);
        self.node.run_refine(&work, self.budget)
    }

    /// [`Flows::batch`], and the gas its refine used.
    pub fn measured(&mut self, after: u64, inputs: Vec<Input>) -> (WorkResult, u64) {
        let invocation = self.refine(after, inputs.clone());
        self.time += after;
        assert_eq!(invocation.exit, vos_pvm::ExitReason::Halt, "refine halts");
        let gas = invocation.gas_used;
        let output = invocation.output_bounded(cap::OUTPUT).unwrap();
        self.node.accumulate(&output);
        self.node.version += 1;
        let (result, _) = split_output(&output).expect("an output");
        self.kit.batch(self.time, [0; 32]);
        self.kit.budget = self.budget;
        // Each due step's row: as a sweep lists it, or a start's, due at
        // once.
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
                    let at = listed.get(workflow).copied().unwrap_or(self.time);
                    self.kit.due(at, *workflow)
                }
                Step::Ran(_) => match inputs.next().expect("an input") {
                    Input::Request(request) => self.kit.command(
                        request.caller,
                        request.instance,
                        request.method,
                        &request.arguments,
                    ),
                    Input::Message(message) => self.kit.message(message.from, &message.body),
                    // Installed in the model as in the node, by `install`.
                    Input::Admin(_) => {
                        self.kit.pass();
                        continue;
                    }
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
        (result, gas)
    }

    /// The sweep of the rows due `after` milliseconds past the last batch.
    pub fn sweeping(&self, after: u64) -> Input {
        self.node.sweep(self.time + after)
    }

    /// A sweep of the rows due `after` milliseconds past the last batch.
    fn sweep(&mut self, after: u64) -> WorkResult {
        let input = self.sweeping(after);
        self.batch(after, vec![input])
    }

    pub fn record(&self, id: u64) -> Workflow {
        self.node
            .value(&keys::workflow(WorkflowId(id)))
            .expect("a workflow")
    }

    /// The pages a workflow's snapshot holds, each with its bytes, as the
    /// node's rows hold them, LZ4-compressed: the model's.
    fn pages(&self, id: u64) -> Vec<(u32, Vec<u8>)> {
        let workflow = WorkflowId(id);
        let held = self
            .record(id)
            .snapshot
            .map(|snapshot| snapshot.pages)
            .unwrap_or_default();
        held.into_iter()
            .map(|(index, _)| {
                let row = self.node.get(&keys::page(workflow, index)).expect("a page");
                let bytes = lz4_flex::block::decompress(&row, 4096).expect("LZ4");
                assert_eq!(Some(&bytes[..]), self.kit.page(workflow, index));
                (index, bytes)
            })
            .collect()
    }

    /// The shop's sales, by its query.
    fn sales(&self) -> u64 {
        let outcome = self
            .node
            .query(ALICE, SHOP, self.method("sales"), ().encode());
        match outcome {
            Outcome::Done(bytes) => decode(&bytes).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    fn count(&self, key: &[u8]) -> Option<u64> {
        self.node.value(key)
    }

    /// A batch `after` milliseconds past the last, refined and accumulated
    /// on the node alone: for what the model does not know, the meter.
    /// The model is behind after it.
    fn unmodelled(&mut self, after: u64, inputs: Vec<Input>) -> WorkResult {
        let invocation = self.refine(after, inputs);
        self.time += after;
        assert_eq!(invocation.exit, vos_pvm::ExitReason::Halt, "refine halts");
        let output = invocation.output_bounded(cap::OUTPUT).unwrap();
        self.node.accumulate(&output);
        self.node.version += 1;
        split_output(&output).expect("an output").0
    }

    /// The caller installed at each of `instances`, in the node and the
    /// model.
    fn callers(&mut self, instances: std::ops::RangeInclusive<u32>) {
        let program = self.node.add(&self.actors.caller);
        let installs = instances
            .clone()
            .map(|instance| crate::common::install(InstanceId(instance), program))
            .collect();
        self.node.batch(self.time, installs);
        for instance in instances {
            self.kit
                .install(InstanceId(instance), &self.actors.caller, &[], &[])
                .unwrap();
        }
        self.kit.version = self.node.version;
    }
}

/// A step of the node's and the model's agree, field by field.
fn agrees(index: usize, run: &Run, expected: &KitStep) {
    assert_eq!(run.outcome, expected.outcome, "step {index}'s outcome");
    assert_eq!(run.writes, expected.writes, "step {index}'s writes");
    assert_eq!(run.committed, expected.committed, "step {index}'s commits");
    assert_eq!(run.messages, expected.messages, "step {index}'s messages");
    assert_eq!(run.attests, expected.attests, "step {index}'s attests");
    assert_eq!(run.pages, expected.pages, "step {index}'s pages");
    assert_eq!(run.instances, expected.instances, "step {index}'s gas");
    assert_eq!(run.gas_used, expected.gas_used, "step {index}'s gas");
}

/// The run of the step a workflow's due step made.
fn due(result: &WorkResult, id: u64) -> &Run {
    let input = InputRef::Due {
        workflow: WorkflowId(id),
    };
    result
        .steps
        .iter()
        .find_map(|step| match step {
            Step::Ran(run) if run.input == input => Some(run),
            _ => None,
        })
        .expect("the workflow's due step")
}

/// The request a workflow sends the risk agent's counter.
fn asks_risk(flows: &Flows, run: &Run, workflow: u64, counter: u64, by: u64) {
    let increment = flows.actors.method(COUNTER, "increment");
    let request = Outgoing {
        to: RISK,
        body: Body::Call {
            instance: COUNTER,
            method: increment,
            arguments: by.encode(),
            awaiting: Some(Await {
                workflow: WorkflowId(workflow),
                counter,
            }),
        },
    };
    assert_eq!(run.messages.last(), Some(&request));
}

/// A transfer's arguments: the risk agent, the ledger, and `amount` from
/// account 1 to account 2, encoded as the method's fields are.
fn transfer(amount: u64) -> impl Encode {
    ((RISK.0, LEDGER.0), (1u64, 2u64, amount))
}

fn ended(record: &Workflow) -> &Outcome {
    match &record.state {
        WorkflowState::Ended(outcome) => outcome,
        other => panic!("not ended: {other:?}"),
    }
}
