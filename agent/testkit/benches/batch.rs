//! The default agent's refine on a real batch, on the interpreter and the
//! JIT: the time per request in a batch of counter increments, and the
//! marginal time of one actor ABI operation, which is one exit from the
//! actor's machine, the agent serving it, and one re-entry. And its
//! accumulate: the time per write of a work result's table writes, and of
//! its committed writes, each a value row and a dirty row, against
//! in-memory storage.
//!
//! And a workflow's step, through the agent: a step of the rounds actor's
//! `rewrite`, which writes every page of its memory each step, restores
//! its snapshot's pages, runs to its next pause, faulting once on each
//! page it writes, and captures them; its refine beyond an empty one's,
//! and its accumulate. A typical suspension holds three pages; the
//! budget, capture plus restore of 50 KB, is 1 ms.
//!
//! `cargo bench -p vos-testkit --bench batch` (after `just build-agent
//! build-test-actors`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

use vos_pvm::accumulate_host::{self, ACCUMULATE_ENTRY, AccumulateContext};
use vos_pvm::inner::gp_call::HISTORICAL_LOOKUP;
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_pvm::refine::Machine;
use vos_pvm::refine_host::{RefineContext, StateReader, serve_lookup};
use vos_pvm::{ExitReason, PvmBackend};
use vos_testkit::programs::{actor, agent, method};
use vos_wire::abi::{cap, code};
use vos_wire::batch::{Admin, Batch, Input, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, WorkflowId};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Workflow, unstored};
use vos_wire::result::{InputRef, Outcome, Step, WorkResult, split_output};
use vos_wire::{Decode, Encode};

const AGENT: AgentId = AgentId(7);
const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
/// The rounds actor, whose workflow the bench steps.
const WORKFLOWS: InstanceId = InstanceId(3);
const ALICE: Principal = Principal::Client([1; 32]);
/// A refine's gas: its batch's budget, and room beyond it for decoding.
const GAS: u64 = 4_000_000_000;
const BUDGET: u64 = vos_wire::defaults::REFINE_GAS;
const ROUNDS: usize = 9;

/// One agent on one backend, with the counter and the ledger installed,
/// running on outer machines as a node does, which serves the agent its
/// programs by hash.
struct Node {
    agent: OuterMachines,
    pool: Arc<MachinePool>,
    programs: HashMap<[u8; 32], Vec<u8>>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Applied state, as refine reads it.
    snapshot: Arc<dyn StateReader>,
    version: u64,
    /// The next batch's time.
    time: u64,
}

/// Serve the agent's `historical_lookup` from `programs`, as a node does
/// ([`serve_lookup`]); any other call it does not serve answers `WHAT`.
fn serve(
    id: u64,
    machine: &mut Machine,
    programs: &HashMap<[u8; 32], Vec<u8>>,
) -> Result<(), ExitReason> {
    if id != u64::from(HISTORICAL_LOOKUP) {
        machine.registers_mut()[7] = code::WHAT;
        return Ok(());
    }
    serve_lookup(machine, u64::from(AGENT.0), |hash| programs.get(hash))
}

impl Node {
    fn new(backend: PvmBackend, agent: &[u8], counter: &[u8], ledger: &[u8]) -> Self {
        let pool = Arc::new(MachinePool::new());
        let mut node = Self {
            agent: OuterMachines::new(agent, backend).unwrap(),
            pool,
            programs: HashMap::new(),
            state: BTreeMap::new(),
            snapshot: Arc::new(BTreeMap::<Vec<u8>, Vec<u8>>::new()),
            version: 0,
            time: 1,
        };
        let inputs = vec![node.install(counter, COUNTER), node.install(ledger, LEDGER)];
        node.apply(inputs);
        node
    }

    /// An install of `blob` as `instance`, its workflows in it, the
    /// program added to the pool and served.
    fn install(&mut self, blob: &[u8], instance: InstanceId) -> Input {
        let program = ProgramHash(self.pool.install(blob).unwrap().0);
        self.programs.insert(program.0, blob.to_vec());
        Input::Admin(Admin::Install {
            instance,
            derivation: vos_testkit::programs::bare(program),
            roles: vec![],
        })
    }

    fn refine(&self, inputs: Vec<Input>) -> Vec<u8> {
        let work = Work::Batch(Batch {
            version: self.version,
            time: self.time,
            seed: [0; 32],
            budget: BUDGET,
            inputs,
        });
        let arguments = RefineArgs::new(u64::from(AGENT.0), work.encode(), [0; 32]).encode();
        let invocation = RefineContext::new(self.agent.load(0, &arguments, GAS).unwrap())
            .with_pool(Arc::clone(&self.pool))
            .with_state(Arc::clone(&self.snapshot))
            .try_run_with_host(|id, machine| serve(id, machine, &self.programs))
            .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt);
        let output = invocation.output_bounded(cap::OUTPUT).unwrap();
        self.agent.restore(invocation);
        output
    }

    fn apply(&mut self, inputs: Vec<Input>) -> WorkResult {
        let result = self.refine(inputs);
        let mut state = std::mem::take(&mut self.state);
        self.accumulate(&result, &mut state);
        self.snapshot = Arc::new(state.clone());
        self.state = state;
        self.version += 1;
        self.time += 1;
        split_output(&result).unwrap().0
    }

    /// Accumulate `result` onto `state`.
    fn accumulate(&self, result: &[u8], state: &mut BTreeMap<Vec<u8>, Vec<u8>>) {
        let inputs = [AccumulateInput::Operand(Operand::new(result.to_vec())).encode()];
        let service = u64::from(AGENT.0);
        let arguments = accumulate_host::arguments(0, service, inputs.len());
        let machine = self.agent.load(ACCUMULATE_ENTRY, &arguments, GAS).unwrap();
        let invocation = AccumulateContext::new(machine, service, &inputs, state)
            .try_run()
            .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt);
        self.agent.restore(invocation);
    }

    /// The median wall time of accumulating `inputs`' result on the
    /// agent's state, in microseconds.
    fn accumulate_time(&self, inputs: Vec<Input>) -> f64 {
        let result = self.refine(inputs);
        let mut rounds: Vec<f64> = (0..ROUNDS)
            .map(|_| {
                let mut state = self.state.clone();
                let started = Instant::now();
                self.accumulate(&result, &mut state);
                started.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        rounds.sort_by(f64::total_cmp);
        rounds[ROUNDS / 2]
    }

    /// The median of a refine's wall time, in microseconds.
    fn time(&self, inputs: &[Input]) -> f64 {
        let result = WorkResult::decode(&self.refine(inputs.to_vec())).unwrap().0;
        for step in &result.steps {
            assert!(
                matches!(step, Step::Ran(run) if matches!(run.outcome, Outcome::Done(_))),
                "{step:?}"
            );
        }
        let mut rounds: Vec<f64> = (0..ROUNDS)
            .map(|_| {
                let started = Instant::now();
                std::hint::black_box(self.refine(inputs.to_vec()));
                started.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        rounds.sort_by(f64::total_cmp);
        rounds[ROUNDS / 2]
    }

    /// The rows of the due index due at the next batch's time, as a leader
    /// lists them.
    fn sweep(&self) -> Input {
        let prefix = keys::due_prefix();
        let due = self
            .state
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, _)| keys::due_entry(key))
            .take_while(|(at, _)| *at <= self.time)
            .take(vos_wire::defaults::SWEEP_LIMIT)
            .collect();
        Input::Sweep { due }
    }

    /// Workflow `id`'s record.
    fn workflow(&self, id: WorkflowId) -> Workflow {
        let bytes = &self.state[&keys::workflow(id)];
        Workflow::decode(unstored(bytes).unwrap()).unwrap().0
    }

    /// The median of a refine's wall time running `inputs`, the step of
    /// workflow `id` among them, in microseconds, and the pages that step
    /// stores; and the median of its result's accumulate.
    fn step_time(&self, inputs: &[Input], id: WorkflowId) -> (f64, usize, f64) {
        let output = self.refine(inputs.to_vec());
        let (result, _) = split_output(&output).unwrap();
        let stored = result
            .steps
            .iter()
            .find_map(|step| match step {
                Step::Ran(run) if run.input == (InputRef::Due { workflow: id }) => {
                    assert_eq!(run.outcome, Outcome::Done(Vec::new()), "it paused");
                    Some(run.pages.len())
                }
                _ => None,
            })
            .expect("the workflow's step");
        let mut rounds: Vec<f64> = (0..ROUNDS)
            .map(|_| {
                let started = Instant::now();
                std::hint::black_box(self.refine(inputs.to_vec()));
                started.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        rounds.sort_by(f64::total_cmp);
        let accumulate = self.accumulate_time(inputs.to_vec());
        (rounds[ROUNDS / 2], stored, accumulate)
    }
}

/// A step of the rounds' `rewrite` writing every page of `bytes`, beside an
/// empty refine: what it takes beyond the empty refine, and the empty
/// refine; the pages its snapshot holds, which it restores, and those it
/// writes and captures; and its accumulate.
fn rewrite_step(
    backend: PvmBackend,
    programs: &Programs,
    bytes: u32,
) -> (f64, f64, usize, usize, f64) {
    let (node, sweep, id) = rewriting(backend, programs, bytes);
    let held = node.workflow(id).snapshot.unwrap().pages.len();
    let empty = node.time(&[]);
    let (step, stored, accumulate) = node.step_time(&[sweep], id);
    (step - empty, empty, held, stored, accumulate)
}

/// A node running the rounds' `rewrite` of `bytes`, stepped until each
/// step writes what the last held: the sweep that runs its next step, and
/// its id.
fn rewriting(backend: PvmBackend, programs: &Programs, bytes: u32) -> (Node, Input, WorkflowId) {
    let mut node = Node::new(
        backend,
        &programs.agent,
        &programs.counter,
        &programs.ledger,
    );
    let rewrite = method(&programs.rounds, "rewrite");
    let install = node.install(&programs.rounds, WORKFLOWS);
    node.apply(vec![install]);
    let start = requests(rewrite, WORKFLOWS, |_| (bytes, u32::MAX).encode(), 1);
    let started = node.apply(start);
    let Step::Ran(run) = &started.steps[0] else {
        panic!("{started:?}")
    };
    let Outcome::Started(id) = run.outcome else {
        panic!("{run:?}")
    };
    // Steps until each one rewrites what the last held.
    for _ in 0..3 {
        node.apply(vec![node.sweep()]);
    }
    let sweep = node.sweep();
    assert!(
        matches!(&sweep, Input::Sweep { due } if due == &[(node.time, Due::Workflow(id))]),
        "{sweep:?}"
    );
    (node, sweep, id)
}

/// The guest programs the bench runs.
struct Programs {
    agent: Vec<u8>,
    counter: Vec<u8>,
    ledger: Vec<u8>,
    rounds: Vec<u8>,
}

fn requests(
    method: MethodId,
    instance: InstanceId,
    arguments: impl Fn(u64) -> Vec<u8>,
    count: u64,
) -> Vec<Input> {
    (1..=count)
        .map(|sequence| {
            Input::Request(Request {
                session: Session {
                    key: [1; 32],
                    name: [1; 16],
                    t0: 1,
                },
                sequence,
                caller: ALICE,
                instance,
                method,
                arguments: arguments(sequence),
            })
        })
        .collect()
}

fn main() {
    let programs = Programs {
        agent: agent(),
        counter: actor("counter"),
        ledger: actor("ledger"),
        rounds: actor("rounds"),
    };
    let (agent, counter, ledger) = (&programs.agent, &programs.counter, &programs.ledger);
    let increment = method(counter, "increment");
    let ops = method(counter, "ops");
    let total = method(ledger, "total");
    // `loop <interpreter|jit> <empty|increments|rewrite:BYTES> <n>`: repeat,
    // for profiling. With `VOS_PVM_PERF_MAP` set, perf names the agent's
    // functions.
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--bench")
        .collect();
    if let [mode, backend, what, count] = args.as_slice()
        && mode == "loop"
    {
        let backend = match backend.as_str() {
            "interpreter" => PvmBackend::ForceInterpreter,
            _ => PvmBackend::ForceRecompiler,
        };
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if std::env::var_os("VOS_PVM_PERF_MAP").is_some() {
            vos_pvm::perf_map::enable().unwrap();
            let elf = std::fs::read(vos_testkit::programs::agent_elf()).unwrap();
            let (blob, functions) = vos_pvm_compiler::link_elf_spi_with_symbols(&elf).unwrap();
            let program = vos_pvm::spi::parse_standard_program(&blob).unwrap();
            vos_pvm::perf_map::register(&program.code.code, functions);
        }
        if let Some(bytes) = what.strip_prefix("rewrite:") {
            let (node, sweep, _) = rewriting(backend, &programs, bytes.parse().unwrap());
            for _ in 0..count.parse::<usize>().unwrap() {
                std::hint::black_box(node.refine(vec![sweep.clone()]));
            }
            return;
        }
        let node = Node::new(backend, agent, counter, ledger);
        let inputs = match what.as_str() {
            "empty" => Vec::new(),
            "split" => {
                // Where an empty refine's time goes: loading the agent's
                // machine, and running it.
                let work = Work::Batch(Batch {
                    version: node.version,
                    time: 1,
                    seed: [0; 32],
                    budget: BUDGET,
                    inputs: Vec::new(),
                });
                let arguments =
                    RefineArgs::new(u64::from(AGENT.0), work.encode(), [0; 32]).encode();
                let (mut load, mut total) = (Vec::new(), Vec::new());
                for _ in 0..count.parse::<usize>().unwrap() {
                    let started = Instant::now();
                    let context = RefineContext::new(node.agent.load(0, &arguments, GAS).unwrap())
                        .with_pool(Arc::clone(&node.pool))
                        .with_state(Arc::new(node.state.clone()));
                    load.push(started.elapsed().as_secs_f64() * 1e6);
                    let invocation = context.try_run_with_host(|_, _| Ok(())).unwrap();
                    node.agent.restore(std::hint::black_box(invocation));
                    total.push(started.elapsed().as_secs_f64() * 1e6);
                }
                load.sort_by(f64::total_cmp);
                total.sort_by(f64::total_cmp);
                println!(
                    "load {:.1} µs of {:.1} µs",
                    load[load.len() / 2],
                    total[total.len() / 2]
                );
                return;
            }
            _ => requests(increment, COUNTER, |_| 1u64.encode(), 200),
        };
        for _ in 0..count.parse::<usize>().unwrap() {
            std::hint::black_box(node.refine(inputs.clone()));
        }
        return;
    }
    for (name, backend) in [
        ("interpreter", PvmBackend::ForceInterpreter),
        ("jit", PvmBackend::ForceRecompiler),
    ] {
        let node = Node::new(backend, agent, counter, ledger);
        let empty = node.time(&[]);
        let batch = requests(increment, COUNTER, |_| 1u64.encode(), 200);
        let per_request = (node.time(&batch) - empty) / 200.0;
        let phases = |count: u32| {
            let arguments = (vec![(1u8, 0u32, count)], (LEDGER.0, total.0)).encode();
            requests(ops, COUNTER, move |_| arguments.clone(), 1)
        };
        let per_op = (node.time(&phases(2000)) - node.time(&phases(0))) / 2000.0 * 1000.0;
        println!(
            "{name:>12}: empty refine {empty:.0} µs; {per_request:.1} µs per increment in a batch of 200; {per_op:.0} ns per `now` operation"
        );
        // A result of one request writing 500 rows, to a table or to a
        // committed map, against one writing none.
        let writes = 500u64;
        let set = method(counter, "set_entries");
        let fill = method(counter, "fill");
        let entries = (0..writes)
            .map(|key| (key * 7919, Some(key)))
            .collect::<Vec<(u64, Option<u64>)>>();
        let none = node.accumulate_time(requests(
            set,
            COUNTER,
            |_| Vec::<(u64, Option<u64>)>::new().encode(),
            1,
        ));
        let committed =
            (node.accumulate_time(requests(set, COUNTER, move |_| entries.encode(), 1)) - none)
                / writes as f64;
        let table = (node.accumulate_time(requests(
            fill,
            COUNTER,
            move |_| (writes as u32, 8u32).encode(),
            1,
        )) - none)
            / writes as f64;
        println!(
            "{name:>12}: accumulate {table:.2} µs per table write, {committed:.2} µs per committed write (value and dirty rows)"
        );
        // A typical suspension, and 50 KB.
        for bytes in [4096u32, 50 << 10] {
            let (step, empty, held, stored, accumulate) = rewrite_step(backend, &programs, bytes);
            println!(
                "{name:>12}: a workflow step rewriting {bytes} bytes, {held} pages restored and {stored} captured: {step:.0} µs beyond an empty refine's {empty:.0} µs; its accumulate {accumulate:.0} µs"
            );
        }
    }
}
