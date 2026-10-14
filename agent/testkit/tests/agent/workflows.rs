//! Workflows: started by a request or a call, stepped by the replies,
//! deadlines and timers that resume them, snapshotted between steps, and
//! ended, failed and collected. Every test runs on the interpreter and the
//! recompiler, every step against the testkit's model, and the two
//! backends agree on every byte.

use std::collections::BTreeMap;

use vos_testkit::programs::{actor, method};
use vos_testkit::{Step as KitStep, Testkit, decode};
use vos_wire::abi::{Failure, cap, op, price};
use vos_wire::batch::{Admin, Answer, Await, Body, Input, Message};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, WorkflowId};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Workflow, WorkflowState, stored};
use vos_wire::result::{InputRef, Outcome, Outgoing, Run, Step, WorkResult, split_output};
use vos_wire::{Encode, defaults};

use crate::common::{ALICE, Actors, COUNTER, LEDGER, Node, SHOP, Sessions, ran};

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
        vos_testkit::program_hash(&self.programs[name])
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

/// A transfer: a request starts it, answered with its id, and its first
/// step follows in the same batch, pausing at its request of the risk
/// agent. The answer resumes it: it moves the funds and counts the sale,
/// and ends with its result, kept for its owner, its pin and its place
/// among the live workflows gone, its collection due. Batches of the
/// default budget.
#[test]
fn a_transfer_awaits_one_answer_then_calls_this_agents_actors() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let mint = flows.actors.method(LEDGER, "mint");
        let minted = flows.sessions.request(ALICE, LEDGER, mint, (1u64, 100u64));
        let start = flows.start("transfer", transfer(30));
        let result = flows.batch(1, vec![minted, start]);
        assert_eq!(
            ran(&result.steps[1]).outcome,
            Outcome::Started(WorkflowId(0))
        );
        let first = due(&result, 0);
        asks_risk(&flows, first, 0, 0, 30);
        let record = flows.record(0);
        assert_eq!(
            record.state,
            WorkflowState::Awaiting {
                agent: RISK,
                counter: 0,
                deadline: flows.time + 30_000,
            }
        );
        assert_eq!(record.owner, ALICE);
        assert_eq!(record.awaits, 1);
        let held = flows.pages(0);
        assert!(!held.is_empty() && held.len() < 16, "{} pages", held.len());
        let program = flows.program("shop");
        assert_eq!(flows.count(&keys::workflow_pins(&program)), Some(1));
        assert_eq!(flows.count(&keys::live_workflows()), Some(1));
        assert!(
            flows
                .node
                .get(&keys::due(
                    flows.time + 30_000,
                    Due::Workflow(WorkflowId(0))
                ))
                .is_some()
        );

        let answer = flows.reply(RISK, 0, 0, Answer::Done(30u64.encode()));
        let result = flows.batch(5, vec![answer]);
        let resumed = ran(&result.steps[0]);
        assert_eq!(resumed.outcome, Outcome::Done(vec![]));
        assert!(resumed.pages.iter().all(|page| page.hash.is_none()));
        let record = flows.record(0);
        assert_eq!(ended(&record), &Outcome::Done(30u64.encode()));
        assert_eq!(record.snapshot, None);
        let collected = flows.time + defaults::WORKFLOW_KEPT_MS;
        assert_eq!(record.due, collected);
        assert!(flows.pages(0).is_empty());
        for (index, _) in held {
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), index)), None);
        }
        assert_eq!(flows.count(&keys::workflow_pins(&program)), None);
        assert_eq!(flows.count(&keys::live_workflows()), None);
        assert_eq!(flows.sales(), 30);
        let balance = flows.actors.method(LEDGER, "balance");
        let balance = |id: u64| flows.node.query(ALICE, LEDGER, balance, id.encode());
        assert_eq!(balance(1), Outcome::Done(70u64.encode()));
        assert_eq!(balance(2), Outcome::Done(30u64.encode()));

        // Collected once its result has been kept long enough.
        let result = flows.sweep(defaults::WORKFLOW_KEPT_MS - 1);
        assert!(result.steps.len() == 1, "not yet: {:?}", result.steps);
        let result = flows.sweep(1);
        assert_eq!(due(&result, 0).writes.len(), 2, "its record and its row");
        assert_eq!(flows.node.get(&keys::workflow(WorkflowId(0))), None);
        assert_eq!(
            flows
                .node
                .get(&keys::due(collected, Due::Workflow(WorkflowId(0)))),
            None
        );
        assert_eq!(flows.count(&keys::live_workflows()), None);
        assert_eq!(flows.count(&keys::next_workflow()), Some(1));
    }
}

/// A saga: five awaits in turn, each answer counted as a sale before the
/// next request, the workflow's memory carried from step to step. Batches
/// of the default budget.
#[test]
fn a_saga_awaits_five_answers() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("saga", (RISK.0, 5u32));
        let result = flows.batch(1, vec![start]);
        asks_risk(&flows, due(&result, 0), 0, 0, 1);
        for step in 0..5u64 {
            let answer = flows.reply(RISK, 0, step, Answer::Done((10 * (step + 1)).encode()));
            let result = flows.batch(1, vec![answer]);
            if step < 4 {
                asks_risk(&flows, ran(&result.steps[0]), 0, step + 1, step + 2);
                assert_eq!(flows.record(0).awaits, step + 2);
            }
        }
        let answers: Vec<u64> = vec![10, 20, 30, 40, 50];
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(answers.encode()));
        assert_eq!(flows.sales(), 150);
    }
}

/// A long computation, pausing at a sleep after filling 2 MiB with
/// pseudo-random words and after each round: its first pause stores every
/// page it wrote, far past the 64 KiB a result takes inline, and its
/// result is the uninterrupted computation's. Batches of the default
/// budget.
#[test]
fn a_long_computation_pauses_at_its_sleeps() {
    for backend in Node::backends() {
        let (words, rounds) = (262_144u32, 16u32);
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("compute", (words, rounds));
        let refined = flows.refine(1, vec![start.clone()]);
        let output = refined.output_bounded(cap::OUTPUT).unwrap();
        assert!(output.len() > 2 << 20, "{} bytes", output.len());
        let result = flows.batch(1, vec![start]);
        let first = due(&result, 0);
        let stored = first
            .pages
            .iter()
            .filter(|page| page.hash.is_some())
            .count();
        assert!((512..600).contains(&stored), "{stored} pages");
        assert!(matches!(
            flows.record(0).state,
            WorkflowState::Sleeping { .. }
        ));
        for _ in 0..=rounds {
            let result = flows.sweep(1);
            assert_eq!(result.steps.len(), 2, "a sweep, then the step");
        }
        let mut data = vec![0u64; words as usize];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for value in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = state;
        }
        let chunk = data.len() / rounds as usize;
        for round in 0..rounds as usize {
            data[round * chunk..(round + 1) * chunk].sort_unstable();
        }
        let mut digest = 0u64;
        for (index, value) in data.iter().enumerate().step_by(997) {
            digest = digest.rotate_left(5) ^ value ^ index as u64;
        }
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(digest.encode()));
    }
}

/// A reply is consumed in its pair's order whatever it answers: one from
/// an agent the workflow does not await, for an await it does not hold, or
/// after its await is gone, is dropped, and the workflow goes on awaiting
/// the one it does.
#[test]
fn replies_from_others_late_or_stale_are_dropped() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let awaiting = flows.record(0);
        let other = AgentId(8);
        let inputs = vec![
            flows.reply(other, 0, 0, Answer::Done(1u64.encode())),
            flows.reply(RISK, 0, 1, Answer::Done(1u64.encode())),
            flows.reply(RISK, 7, 0, Answer::Done(1u64.encode())),
        ];
        let result = flows.batch(1, inputs);
        for step in &result.steps {
            let run = ran(step);
            assert_eq!(run.outcome, Outcome::Done(vec![]));
            assert!(run.writes.is_empty() && run.messages.is_empty() && run.pages.is_empty());
        }
        assert_eq!(flows.record(0), awaiting, "still awaiting the risk agent");
        assert_eq!(flows.count(&keys::pair_in(other)), Some(1));
        assert_eq!(flows.count(&keys::pair_in(RISK)), Some(2));

        let answer = flows.reply(RISK, 0, 0, Answer::Done(0u64.encode()));
        let again = flows.reply(RISK, 0, 0, Answer::Done(0u64.encode()));
        let result = flows.batch(1, vec![answer, again]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(0u64.encode()));
        let late = ran(&result.steps[1]);
        assert!(
            late.writes.is_empty() && late.pages.is_empty(),
            "the late one"
        );
        assert_eq!(flows.count(&keys::pair_in(RISK)), Some(4));
    }
}

/// An await's deadline is batch time: the step at it answers the await
/// `TimedOut`, and a reply at or after it is dropped, before that step as
/// after. A timer wakes its workflow in the first sweep at or past it.
#[test]
fn deadlines_expire_and_timers_fire_at_batch_time() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let transfer = flows.start("transfer", transfer(5));
        let nap = flows.start("nap", 5_000u64);
        let result = flows.batch(1, vec![transfer, nap]);
        assert_eq!(result.steps.len(), 4, "two starts, each with its step");
        let started = flows.time;
        assert_eq!(
            flows.record(1).state,
            WorkflowState::Sleeping {
                until: started + 5_000
            }
        );
        let result = flows.sweep(4_999);
        assert_eq!(result.steps.len(), 1, "nothing due yet");
        let result = flows.sweep(1);
        let woke = due(&result, 1);
        assert_eq!(woke.outcome, Outcome::Done(vec![]));
        assert_eq!(
            ended(&flows.record(1)),
            &Outcome::Done((started + 5_000).encode())
        );

        let result = flows.sweep(25_000 - 1);
        assert_eq!(result.steps.len(), 1, "the deadline is not yet");
        // A reply at the deadline, before the deadline's step: dropped, the
        // deadline being batch time.
        let at_deadline = flows.reply(RISK, 0, 0, Answer::Done(5u64.encode()));
        let awaiting = flows.record(0);
        let result = flows.batch(1, vec![at_deadline]);
        assert!(ran(&result.steps[0]).writes.is_empty());
        assert_eq!(flows.record(0), awaiting);
        let result = flows.sweep(0);
        due(&result, 0);
        // The shop's `ShopError::TimedOut`.
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Failed {
                code: Failure::Handler,
                detail: vec![1],
            }
        );
        let late = flows.reply(RISK, 0, 0, Answer::Done(5u64.encode()));
        let result = flows.batch(1, vec![late]);
        assert!(ran(&result.steps[0]).writes.is_empty());
        assert_eq!(flows.sales(), 0);
    }
}

/// A step that traps fails its workflow: its own effects go, the earlier
/// steps' stay, and the workflow ends failed, its pages and pin gone.
#[test]
fn a_trap_fails_the_workflow_and_keeps_its_earlier_steps() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("fragile", RISK.0);
        flows.batch(1, vec![start]);
        assert_eq!(flows.sales(), 1, "the first step's sale");
        let held = flows.pages(0);
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.batch(1, vec![answer]);
        let trapped = ran(&result.steps[0]);
        assert_eq!(
            trapped.outcome,
            Outcome::Failed {
                code: Failure::Trapped,
                detail: vec![],
            }
        );
        assert_eq!(trapped.pages.len(), held.len());
        assert!(trapped.pages.iter().all(|page| page.hash.is_none()));
        assert_eq!(flows.sales(), 1, "the trapping step's sale went");
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Failed {
                code: Failure::Trapped,
                detail: vec![],
            }
        );
        let program = flows.program("shop");
        assert_eq!(flows.count(&keys::workflow_pins(&program)), None);
        for (index, _) in held {
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), index)), None);
        }
    }
}

/// A page written back to its base, zeros or the program's image, is
/// dropped: its row goes, and a restore gives the base again.
#[test]
fn pages_written_back_to_their_base_are_dropped() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("scratch", RISK.0);
        flows.batch(1, vec![start]);
        let first = flows.pages(0);
        let marked: Vec<u32> = first
            .iter()
            .filter(|(_, bytes)| {
                bytes.iter().all(|byte| *byte == 0xab) || bytes.iter().all(|byte| *byte == 0x55)
            })
            .map(|(index, _)| *index)
            .collect();
        assert_eq!(marked.len(), 2, "the zeroed page and the image's");
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.batch(1, vec![answer]);
        let dropped: Vec<u32> = ran(&result.steps[0])
            .pages
            .iter()
            .filter(|page| page.hash.is_none())
            .map(|page| page.index)
            .collect();
        for index in &marked {
            assert!(dropped.contains(index), "page {index:#x} dropped");
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), *index)), None);
        }
        let answer = flows.reply(RISK, 0, 1, Answer::Done(1u64.encode()));
        flows.batch(1, vec![answer]);
        let sums = (4096 * (0xab + 0x55u64), 4096 * 7u64);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(sums.encode()));
    }
}

/// An agent that starts a workflow is answered `Started` with its id, and
/// its wait for the result is answered once the workflow ends, or at once
/// when it has; only the owner may wait.
#[test]
fn an_owning_agent_waits_for_a_result_by_its_id() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let owner = AgentId(5);
        let nap = flows.method("nap");
        let theirs = Await {
            workflow: WorkflowId(70),
            counter: 0,
        };
        let call = Body::Call {
            instance: SHOP,
            method: nap,
            arguments: 1_000u64.encode(),
            awaiting: Some(theirs),
        };
        let start = flows.message(owner, call);
        let result = flows.batch(1, vec![start]);
        let started = Outgoing {
            to: owner,
            body: Body::Reply {
                awaiting: theirs,
                answer: Answer::Started(WorkflowId(0)),
            },
        };
        assert_eq!(ran(&result.steps[0]).messages, [started]);
        assert_eq!(flows.record(0).owner, Principal::Agent(owner));

        let second = Await {
            counter: 1,
            ..theirs
        };
        let wait = flows.message(
            owner,
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: second,
            },
        );
        let stranger = flows.message(
            AgentId(6),
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: theirs,
            },
        );
        let result = flows.batch(1, vec![wait, stranger]);
        assert!(
            ran(&result.steps[0]).messages.is_empty(),
            "held until it ends"
        );
        assert_eq!(flows.record(0).waiter, Some(second));
        let unknown = Answer::Failed {
            code: Failure::Unknown,
            detail: vec![],
        };
        assert_eq!(
            ran(&result.steps[1]).messages[0].body,
            Body::Reply {
                awaiting: theirs,
                answer: unknown,
            }
        );

        let result = flows.sweep(1_000);
        let woke = flows.time;
        let answered = Outgoing {
            to: owner,
            body: Body::Reply {
                awaiting: second,
                answer: Answer::Done(woke.encode()),
            },
        };
        assert_eq!(due(&result, 0).messages, [answered]);
        assert_eq!(flows.record(0).waiter, None);

        let third = Await {
            counter: 2,
            ..theirs
        };
        let again = flows.message(
            owner,
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: third,
            },
        );
        let result = flows.batch(1, vec![again]);
        assert_eq!(
            ran(&result.steps[0]).messages[0].body,
            Body::Reply {
                awaiting: third,
                answer: Answer::Done(woke.encode()),
            }
        );
    }
}

/// A workflow starts another agent's workflow and awaits its result: two
/// awaits, the first answered `Started`, the second with the result.
#[test]
fn a_workflow_starts_another_agents_and_awaits_its_result() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("delegate", (RISK.0, SHOP.0, 500u64));
        let result = flows.batch(1, vec![start]);
        let nap = flows.method("nap");
        let starting = Outgoing {
            to: RISK,
            body: Body::Call {
                instance: SHOP,
                method: nap,
                arguments: 500u64.encode(),
                awaiting: Some(Await {
                    workflow: WorkflowId(0),
                    counter: 0,
                }),
            },
        };
        assert_eq!(due(&result, 0).messages, [starting]);
        let started = flows.reply(RISK, 0, 0, Answer::Started(WorkflowId(77)));
        let result = flows.batch(1, vec![started]);
        let waiting = Outgoing {
            to: RISK,
            body: Body::Wait {
                workflow: WorkflowId(77),
                awaiting: Await {
                    workflow: WorkflowId(0),
                    counter: 1,
                },
            },
        };
        assert_eq!(ran(&result.steps[0]).messages, [waiting]);
        let result_in = flows.reply(RISK, 0, 1, Answer::Done(12_345u64.encode()));
        flows.batch(1, vec![result_in]);
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done((WorkflowId(77), 12_345u64).encode())
        );
    }
}

/// A workflow keeps the program it started on, its instance's actor
/// program, whatever an upgrade installs meanwhile: it pins it until it
/// ends.
#[test]
fn a_workflow_keeps_its_program_through_an_upgrade() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let upgrade = flows.install("lean");
        let result = flows.batch(1, vec![upgrade]);
        ran(&result.steps[0]);
        let shop = flows.program("shop");
        assert_eq!(flows.record(0).program, shop);
        assert_eq!(flows.count(&keys::workflow_pins(&shop)), Some(1));
        let answer = flows.reply(RISK, 0, 0, Answer::Done(9u64.encode()));
        flows.batch(1, vec![answer]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(9u64.encode()));
        assert_eq!(flows.count(&keys::workflow_pins(&shop)), None);

        // A start now runs the program installed since.
        let start = flows.start("transfer", transfer(0));
        let result = flows.batch(1, vec![start]);
        assert_eq!(flows.record(1).program, flows.program("lean"));
        asks_risk(&flows, due(&result, 1), 1, 0, 0);
    }
}

/// The caps: a start past the agent's workflows fails, as does one of a
/// program that may write more than a workflow's pages; a step that writes
/// past its pages, or would leave its snapshot holding more than it may,
/// fails its workflow.
#[test]
fn the_caps_hold() {
    for backend in Node::backends() {
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        let mut flows = Flows::new(Node::on(backend));
        flows.node.state.insert(
            keys::live_workflows(),
            stored(&(defaults::MAX_WORKFLOWS - 1).encode()),
        );
        let inputs = vec![flows.start("nap", 1u64), flows.start("nap", 1u64)];
        let work = flows.node.work(flows.time + 1, inputs);
        let result = split_output(&flows.node.refine(&work)).unwrap().0;
        assert_eq!(
            ran(&result.steps[0]).outcome,
            Outcome::Started(WorkflowId(0))
        );
        assert_eq!(ran(&result.steps[2]).outcome, cap, "one past the agent's");

        let mut flows = Flows::new(Node::on(backend));
        let install = flows.install("huge");
        flows.batch(1, vec![install]);
        let start = flows.start("hog", 1u32);
        let result = flows.batch(1, vec![start]);
        assert_eq!(ran(&result.steps[0]).outcome, cap, "a program too large");

        let mut flows = Flows::new(Node::on(backend));
        let install = flows.install("big");
        flows.batch(1, vec![install]);
        let past = (cap::STEP_PAGES + 4096) as u32;
        let start = flows.start("hog", past);
        let result = flows.batch(1, vec![start]);
        assert_eq!(
            due(&result, 0).outcome,
            cap,
            "a step writing past its pages"
        );
        assert_eq!(ended(&flows.record(0)), &cap);
    }
}

/// A batch as a scenario ran it: its refine's output, the gas the refine
/// used, and the state after it.
type Ran = (Vec<u8>, u64, BTreeMap<Vec<u8>, Vec<u8>>);

/// A scenario of workflows that await, compute and write their memory
/// back, and are preempted: at the start of a block, at a call of this
/// agent's once their share is spent, at a first effect a tight batch
/// cannot cover, and at a page it cannot pay. Run on `node`, batch by
/// batch.
fn scenario(node: Node) -> Vec<Ran> {
    let mut flows = Flows::new(node);
    let mut batches = Vec::new();
    let mut run = |flows: &mut Flows, budget: u64, inputs: Vec<Input>| {
        flows.time += 1;
        let work = flows
            .node
            .budgeted_work(flows.time, [0; 32], budget, inputs);
        let invocation = flows.node.run_refine(&work, crate::common::OUTER_GAS);
        assert_eq!(invocation.exit, vos_pvm::ExitReason::Halt, "refine halts");
        let output = invocation.output_bounded(cap::OUTPUT).unwrap();
        flows.node.accumulate(&output);
        flows.node.version += 1;
        let result = split_output(&output).unwrap().0;
        batches.push((output, invocation.gas_used, flows.node.state.clone()));
        result
    };
    let budget = defaults::REFINE_GAS;
    let starts = vec![
        flows.start("transfer", transfer(0)),
        flows.start("compute", (16_384u32, 2u32)),
        flows.start("scratch", RISK.0),
    ];
    run(&mut flows, budget, starts);
    let answers = vec![
        flows.reply(RISK, 0, 0, Answer::Done(1u64.encode())),
        flows.reply(RISK, 2, 0, Answer::Done(1u64.encode())),
    ];
    run(&mut flows, budget, answers);
    for _ in 0..3 {
        let sweep = flows.node.sweep(flows.time + 1);
        run(&mut flows, budget, vec![sweep]);
    }
    let answer = flows.reply(RISK, 2, 1, Answer::Done(1u64.encode()));
    run(&mut flows, budget, vec![answer]);

    // Preempted: at blocks' starts, at calls once the share is spent, at a
    // first effect a tight batch cannot cover, and at pages one cannot pay.
    let starts = vec![
        flows.start("grind", (4096u32, 200u32)),
        flows.start("relay", relayed(2)),
    ];
    run(&mut flows, budget, starts);
    let start = flows.start("settle", settle_rounds());
    run(&mut flows, SETTLE_LIMIT + SETTLE_LIMIT / 2, vec![start]);
    let pending = flows.record(5).snapshot.unwrap().pending;
    assert_eq!(pending, Some(op::CALL));
    // Some 200 pages held, restored a step, and room for 25 more.
    let start = flows.start("grind", (100_000u32, 1u32));
    let tight = defaults::WORKFLOW_RESERVE
        + 1100 * defaults::ARM_PAGE
        + 200 * defaults::RESTORED_PAGE
        + GRIND_LIMIT
        + defaults::FINISH_RESERVE
        + defaults::SWEEP_RESERVE
        + 25 * defaults::WRITTEN_PAGE;
    run(&mut flows, tight, vec![start]);
    let (first, last) = (3, 6);
    let limit = flows.record(last).gas;
    assert_eq!(limit, GRIND_LIMIT);
    let mut short = 0;
    for _ in 0..40 {
        if (first..=last).all(|id| matches!(flows.record(id).state, WorkflowState::Ended(_))) {
            break;
        }
        let sweep = flows.node.sweep(flows.time + 1);
        let result = run(&mut flows, tight, vec![sweep]);
        let stepped = result.steps.iter().any(|step| {
            matches!(step, Step::Ran(run) if run.input == InputRef::Due { workflow: WorkflowId(last) }
                && run.gas_used < limit)
        });
        if stepped && matches!(flows.record(last).state, WorkflowState::Preempted(_)) {
            short += 1;
        }
    }
    assert!(short > 0, "preempted at a page it could not pay");
    for workflow in 0..=last {
        let record = flows.record(workflow);
        let outcome = ended(&record);
        assert!(
            matches!(outcome, Outcome::Done(_)),
            "{workflow}: {outcome:?}"
        );
    }
    let stored: usize = batches
        .iter()
        .map(|(output, ..)| split_output(output).unwrap().1.len())
        .sum();
    assert!(stored > 16, "{stored} pages compared");
    batches
}

/// The interpreter and the recompiler agree on every byte of every batch:
/// each step's gas and snapshot, and the pages that ride beside the work
/// result.
#[test]
fn the_interpreter_and_the_recompiler_agree() {
    let runs: Vec<_> = Node::backends()
        .into_iter()
        .map(Node::on)
        .map(scenario)
        .collect();
    for other in &runs[1..] {
        assert_eq!(other.len(), runs[0].len());
        for (index, ((output, ..), (expected, ..))) in other.iter().zip(&runs[0]).enumerate() {
            assert!(output == expected, "batch {index} differs");
        }
    }
}

/// A VOS host and a JAM host, which reads applied state as JAM mode's
/// witnesses will give it, agree on every byte of every workflow batch and
/// on the state after it, though the JAM host's agent hashes the pages in
/// software, at an outer gas of its own.
#[test]
fn vos_and_jam_hosts_agree_on_workflow_batches() {
    let vos = scenario(Node::new());
    let jam = scenario(Node::jam(true));
    assert_eq!(vos.len(), jam.len());
    for (index, ((on_vos, vos_gas, vos_state), (on_jam, jam_gas, jam_state))) in
        vos.iter().zip(&jam).enumerate()
    {
        assert!(on_vos == on_jam, "batch {index} differs");
        assert!(vos_state == jam_state, "the state after batch {index}");
        assert_ne!(vos_gas, jam_gas, "batch {index}: the outer gas differs");
    }
}

/// A workflow's machine counts toward the machines a step may hold, though
/// it is on no call stack: its chain of nested calls fails one call shorter
/// than a handler's, on the depth rule, never on the host's machines.
#[test]
fn a_workflows_nested_calls_count_its_own_machine() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.callers(100..=170);
        let inputs = vec![
            flows.start("chain", (100u32, 61u32)),
            flows.start("chain", (100u32, 62u32)),
        ];
        let result = flows.batch(1, inputs);
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(61u32.encode()));
        let depth = Outcome::Failed {
            code: Failure::Depth,
            detail: vec![],
        };
        assert_eq!(due(&result, 1).outcome, depth, "a sixty-fourth machine");
        assert_eq!(ended(&flows.record(1)), &depth);
    }
}

/// An attest a workflow's call makes commits with the step's snapshot.
#[test]
fn a_nested_attest_commits_with_its_step() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let values = vec![1u64, 2, 3];
        let start = flows.start("audit", (LEDGER.0, values.clone()));
        let result = flows.batch(1, vec![start]);
        let attests = &due(&result, 0).attests;
        assert_eq!(attests.len(), 1);
        assert_eq!(attests[0].arguments, values.encode());
        let checksum = attests[0].output.clone();
        flows.sweep(1);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(checksum));
    }
}

/// A precompile the agent serves writes its output into a page the
/// workflow never wrote itself, through the agent's tracked write: the
/// page is held, restored, and written again, step after step.
#[test]
fn a_precompiles_output_is_tracked_across_pauses() {
    let rounds = 3u32;
    let mut h = [0u64; 8];
    for round in 0..rounds {
        let block = [u64::from_le_bytes([round as u8; 8]); 16];
        let counter = u128::from(round + 1) * 128;
        h = vos_pvm::precompile::compress(&h, &block, counter, round + 1 == rounds);
    }
    let digest: Vec<u8> = h.iter().flat_map(|word| word.to_le_bytes()).collect();
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("digest", rounds);
        let result = flows.batch(1, vec![start]);
        let stored = due(&result, 0)
            .pages
            .iter()
            .filter(|page| page.hash.is_some())
            .count();
        assert!(stored >= 2, "the stack's and the state's: {stored}");
        for _ in 0..rounds {
            flows.sweep(1);
        }
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done(digest[..32].to_vec().encode())
        );
    }
}

/// Two steps of one workflow in one batch: the second, resumed by a reply,
/// restores the pages the first stored, from the batch's own writes.
#[test]
fn a_workflow_steps_twice_in_one_batch() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
        let result = flows.batch(1, vec![start, answer]);
        assert_eq!(result.steps.len(), 3, "the start, its step, the reply's");
        assert!(due(&result, 0).pages.iter().any(|page| page.hash.is_some()));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));
    }
}

/// A workflow's request of its own agent traps: it calls it instead.
#[test]
fn a_request_of_its_own_agent_traps() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("saga", (crate::common::AGENT.0, 1u32));
        let result = flows.batch(1, vec![start]);
        let trapped = Outcome::Failed {
            code: Failure::Trapped,
            detail: vec![],
        };
        assert_eq!(due(&result, 0).outcome, trapped);
    }
}

/// A sleep until the batch's own time lies a millisecond ahead: a sweep in
/// the same millisecond leaves it, and the next wakes it, so the head of
/// the due index never stays where a sweep left it.
#[test]
fn a_sleep_lies_ahead_of_its_own_batch() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("nap", 0u64);
        flows.batch(1, vec![start]);
        let slept = flows.time;
        assert_eq!(
            flows.record(0).state,
            WorkflowState::Sleeping { until: slept + 1 }
        );
        let result = flows.sweep(0);
        assert_eq!(result.steps.len(), 1, "not in its own millisecond");
        let result = flows.sweep(1);
        due(&result, 0);
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done((slept + 1).encode())
        );
    }
}

/// A row of the due index whose workflow is gone, or whose workflow's
/// record lies elsewhere, is deleted by the step it makes, and nothing
/// else moves.
#[test]
fn orphan_and_stale_rows_of_the_due_index_go() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("nap", 60_000u64);
        flows.batch(1, vec![start]);
        let record = flows.record(0);
        let stale = keys::due(flows.time, Due::Workflow(WorkflowId(0)));
        let orphan = keys::due(flows.time, Due::Workflow(WorkflowId(9)));
        for row in [&stale, &orphan] {
            flows.node.state.insert(row.clone(), stored(&[]));
        }
        let result = flows.sweep(1);
        assert_eq!(result.steps.len(), 3, "the sweep, then each row's step");
        assert_eq!(flows.node.get(&stale), None);
        assert_eq!(flows.node.get(&orphan), None);
        assert_eq!(flows.record(0), record, "the workflow sleeps on");
        assert!(
            flows
                .node
                .get(&keys::due(record.due, Due::Workflow(WorkflowId(0))))
                .is_some()
        );
    }
}

/// Only workflows that have not ended count toward the agent's: one that
/// ends makes room for a start, though its result is kept.
#[test]
fn ended_workflows_leave_room_for_starts() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.node.state.insert(
            keys::live_workflows(),
            stored(&(defaults::MAX_WORKFLOWS - 1).encode()),
        );
        let live = (defaults::MAX_WORKFLOWS - 1).encode();
        flows.kit.set_row(keys::live_workflows(), live);
        let inputs = vec![flows.start("nap", 0u64), flows.start("nap", 0u64)];
        let result = flows.batch(1, inputs);
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        assert_eq!(ran(&result.steps[2]).outcome, cap, "one past the agent's");
        flows.sweep(1);
        ended(&flows.record(0));
        let start = flows.start("nap", 0u64);
        let result = flows.batch(1, vec![start]);
        assert_eq!(
            ran(&result.steps[0]).outcome,
            Outcome::Started(WorkflowId(1))
        );
    }
}

/// The agent's state lost data it wrote: a page row gone, or not what its
/// hash says, or a record that does not decode. The refine stops at the
/// agent's report to the node, which halts, rather than fail the workflow
/// or drop its reply as their fault.
#[test]
fn lost_workflow_state_stops_the_refine() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let (index, _) = flows.pages(0)[0];
        let row = keys::page(WorkflowId(0), index);
        let held = flows.node.state[&row].clone();
        let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
        let mut corrupt = held.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let record = keys::workflow(WorkflowId(0));
        let kept = flows.node.state[&record].clone();
        for (key, value) in [
            (row.clone(), None),
            (row.clone(), Some(corrupt)),
            (record.clone(), Some(stored(&[9]))),
        ] {
            match value {
                Some(value) => flows.node.state.insert(key.clone(), value),
                None => flows.node.state.remove(&key),
            };
            let refined = flows.refine(1, vec![answer.clone()]);
            assert_eq!(
                refined.exit,
                vos_pvm::ExitReason::HostCall(crate::common::LOST),
                "{key:?}"
            );
            flows.node.state.insert(row.clone(), held.clone());
            flows.node.state.insert(record.clone(), kept.clone());
        }
        flows.batch(1, vec![answer]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));
    }
}

/// The meter: pages a unit writes after its first effect cannot end the
/// step there, so a step whose pages overrun the budget then waits for the
/// next batch behind a step that ran a handler, and fails alone, out of
/// gas; before any effect, the step ends at the first page it cannot pay,
/// and is taken. One no batch of the budget could hold fails at once, past
/// a cap.
#[test]
fn the_meter_holds_workflows_steps() {
    let out_of_gas = Outcome::Failed {
        code: Failure::OutOfGas,
        detail: vec![],
    };
    let cap = Outcome::Failed {
        code: Failure::Cap,
        detail: vec![],
    };
    for backend in Node::backends() {
        // A hundred pages after a send, in a batch of 150M.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 150_000_000;
        let increment = flows.actors.method(COUNTER, "increment");
        let handler = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
        let start = flows.start("splurge", (RISK.0, 100 * 4096u32));
        let result = flows.unmodelled(1, vec![handler, start]);
        assert_eq!(result.steps.len(), 2, "the step waits behind the handler");
        assert!(matches!(flows.record(0).state, WorkflowState::Ready(_)));
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![sweep]);
        assert_eq!(due(&result, 0).outcome, out_of_gas, "alone, it fails");
        assert!(due(&result, 0).messages.is_empty(), "its send discarded");
        assert_eq!(ended(&flows.record(0)), &out_of_gas);

        // A hundred pages before any effect: the reply's step is taken,
        // preempted at the first page the budget cannot pay.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 150_000_000;
        let start = flows.start("fill", (RISK.0, vec![4096u32, 100 * 4096]));
        flows.unmodelled(1, vec![start]);
        let handler = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.unmodelled(1, vec![handler, answer]);
        assert_eq!(result.steps.len(), 2, "the reply's step is taken");
        assert!(matches!(flows.record(0).state, WorkflowState::Preempted(_)));

        // A step no batch of the budget could hold fails at once.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 100_000_000;
        let start = flows.start("compute", (16u32, 1u32));
        let result = flows.batch(1, vec![start]);
        assert_eq!(due(&result, 0).outcome, cap);
        assert_eq!(ended(&flows.record(0)), &cap);
    }
}

/// The pages a step may move, in a refine of the default budget: one that
/// restores most of what a snapshot may hold has room left for a few
/// hundred written, and ends at the first it cannot pay; holding then more
/// than a snapshot may, it fails past the cap.
#[test]
fn restored_and_written_pages_share_the_budget() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let install = flows.install("big");
        flows.batch(1, vec![install]);
        let start = flows.start("fill", (0u32, vec![700 * 4096u32, 300 * 4096]));
        let result = flows.unmodelled(1, vec![start]);
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        let held = flows.record(0).snapshot.unwrap().pages.len();
        assert!((700..=cap::HELD_PAGES).contains(&held), "{held} held");
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![sweep]);
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        assert_eq!(due(&result, 0).outcome, cap);
    }
}

/// A step whose pages would pass what a result's page section holds waits
/// for the next batch, its row due.
#[test]
fn a_result_holds_at_most_its_pages() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 8_000_000_000;
        let fill = |flows: &mut Flows| flows.start("fill", (0u32, vec![640 * 4096u32]));
        let inputs = (0..7).map(|_| fill(&mut flows)).collect();
        let result = flows.unmodelled(1, inputs);
        let stepped = |result: &WorkResult| {
            result
                .steps
                .iter()
                .filter(|step| {
                    matches!(
                        step,
                        Step::Ran(Run {
                            input: InputRef::Due { .. },
                            ..
                        })
                    )
                })
                .count()
        };
        assert_eq!(stepped(&result), 6, "a seventh's pages would pass the cap");
        assert!(matches!(flows.record(6).state, WorkflowState::Ready(_)));
        let sweep = flows.sweeping(0);
        let result = flows.unmodelled(0, vec![sweep]);
        assert_eq!(stepped(&result), 1);
        assert!(matches!(
            flows.record(6).state,
            WorkflowState::Sleeping { .. }
        ));
    }
}

/// A program the agent's state pins, a workflow's or an installed
/// instance's, that a VOS node no longer holds is data the node lost: the
/// refine stops rather than fail the step for the node's fault. A JAM
/// node's preimages lacking it fail the workflow, `Unloadable`.
#[test]
fn a_lost_pinned_program_stops_the_refine() {
    let mut flows = Flows::new(Node::new());
    let start = flows.start("transfer", transfer(0));
    flows.batch(1, vec![start]);
    let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
    let program = flows.program("shop");
    let blob = flows.node.forget(&program);
    let refined = flows.refine(1, vec![answer.clone()]);
    let lost = vos_pvm::ExitReason::HostCall(crate::common::LOST);
    assert_eq!(refined.exit, lost, "a workflow's program");
    flows.node.add(&blob);
    let counter = flows
        .node
        .forget(&vos_testkit::program_hash(&flows.actors.counter));
    let increment = flows.actors.method(COUNTER, "increment");
    let request = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
    assert_eq!(flows.refine(1, vec![request]).exit, lost, "a handler's");
    flows.node.add(&counter);
    flows.batch(1, vec![answer]);
    assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));

    let mut flows = Flows::new(Node::jam(true));
    let start = flows.start("transfer", transfer(0));
    flows.unmodelled(1, vec![start]);
    let program = flows.program("shop");
    flows.node.forget(&program);
    let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
    flows.unmodelled(1, vec![answer]);
    let unloadable = Outcome::Failed {
        code: Failure::Unloadable,
        detail: vec![],
    };
    assert_eq!(ended(&flows.record(0)), &unloadable);
}

/// A page section near its cap, of random pages: seven computations each
/// store some 514 pages in one batch of a large budget, and the agent's
/// heap holds the section, reserved once, its pages stored in it as they
/// are compressed. An eighth's would pass the cap, so its step waits.
#[test]
fn a_page_section_near_its_cap_fits_the_heap() {
    let mut flows = Flows::new(Node::new());
    flows.budget = 6_000_000_000;
    let starts = (0..8)
        .map(|_| flows.start("compute", (262_144u32, 1u32)))
        .collect();
    let result = flows.unmodelled(1, starts);
    let stored: usize = result
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Ran(run) => Some(run.pages.len()),
            _ => None,
        })
        .sum();
    let cap = cap::RESULT_PAGES / vos_wire::result::PAGE;
    assert!(stored > 3 * cap / 4 && stored <= cap, "{stored} pages");
    assert!(matches!(flows.record(7).state, WorkflowState::Ready(_)));
    let sweep = flows.sweeping(1);
    flows.unmodelled(1, vec![sweep]);
    assert!(matches!(
        flows.record(7).state,
        WorkflowState::Sleeping { .. }
    ));
}
