//! The default agent's refine on a real batch, on the interpreter and the
//! JIT: the time per request in a batch of counter increments, and the
//! marginal time of one actor ABI operation, which is one exit from the
//! actor's machine, the agent serving it, and one re-entry.
//!
//! `cargo bench -p vos-testkit --bench batch` (after `just build-agent
//! build-test-actors`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use vos_pvm::accumulate_host::{self, ACCUMULATE_ENTRY, AccumulateContext, ServiceStorage};
use vos_pvm::pool::{MachinePool, OuterMachines};
use vos_pvm::refine_host::{RefineContext, StateReader};
use vos_pvm::{ExitReason, PvmBackend};
use vos_testkit::programs::{actor, agent, method};
use vos_wire::abi::cap;
use vos_wire::batch::{Admin, Batch, Input, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::result::{Outcome, Step, WorkResult};
use vos_wire::{Decode, Encode};

const AGENT: AgentId = AgentId(7);
const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
const ALICE: Principal = Principal::Client([1; 32]);
const GAS: u64 = 4_000_000_000;
const ROUNDS: usize = 9;

struct Snapshot(BTreeMap<Vec<u8>, Vec<u8>>);

impl StateReader for Snapshot {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        Box::new(
            self.0
                .range(prefix.to_vec()..)
                .take_while(move |(key, _)| key.starts_with(prefix))
                .filter(move |(key, _)| after.is_none_or(|after| key.as_slice() > after))
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }
}

struct Storage<'a>(&'a mut BTreeMap<Vec<u8>, Vec<u8>>);

impl ServiceStorage for Storage<'_> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match value {
            Some(value) => self.0.insert(key.to_vec(), value.to_vec()),
            None => self.0.remove(key),
        };
        previous.map(|value| value.len())
    }
}

/// One agent on one backend, with the counter and the ledger installed,
/// running on outer machines as a node does.
struct Node {
    agent: OuterMachines,
    pool: Arc<MachinePool>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    version: u64,
}

impl Node {
    fn new(backend: PvmBackend, agent: &[u8], counter: &[u8], ledger: &[u8]) -> Self {
        let pool = Arc::new(MachinePool::new());
        let mut node = Self {
            agent: OuterMachines::new(agent, backend).unwrap(),
            pool,
            state: BTreeMap::new(),
            version: 0,
        };
        let install = |blob: &[u8], instance| {
            let program = ProgramHash(node.pool.install(blob).unwrap().0);
            Input::Admin(Admin::Install {
                instance,
                program,
                attestables: vec![],
                roles: vec![],
            })
        };
        let inputs = vec![install(counter, COUNTER), install(ledger, LEDGER)];
        node.apply(inputs);
        node
    }

    fn refine(&self, inputs: Vec<Input>) -> Vec<u8> {
        let work = Work::Batch(Batch {
            version: self.version,
            time: 1,
            seed: [0; 32],
            budget: GAS,
            inputs,
        });
        let arguments = RefineArgs {
            core: 0,
            item: 0,
            service: u64::from(AGENT.0),
            payload: work.encode(),
            package_hash: [0; 32],
        }
        .encode();
        let invocation = RefineContext::new(self.agent.load(0, &arguments, GAS).unwrap())
            .with_pool(Arc::clone(&self.pool))
            .with_state(Arc::new(Snapshot(self.state.clone())))
            .try_run_with_host(|_, machine| {
                machine.registers_mut()[7] = vos_wire::abi::code::WHAT;
                Ok(())
            })
            .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt);
        let output = invocation.output_bounded(cap::WORK_RESULT).unwrap();
        self.agent.restore(invocation);
        output
    }

    fn apply(&mut self, inputs: Vec<Input>) {
        let result = self.refine(inputs);
        let input = AccumulateInput::Operand(Operand {
            package_hash: [0; 32],
            segment_root: [0; 32],
            authorizer: [0; 32],
            payload_hash: [0; 32],
            gas_limit: 0,
            result: Ok(result),
            auth_trace: Vec::new(),
        })
        .encode();
        let inputs = [input];
        let service = u64::from(AGENT.0);
        let arguments = accumulate_host::arguments(0, service, inputs.len());
        let machine = self.agent.load(ACCUMULATE_ENTRY, &arguments, GAS).unwrap();
        let invocation =
            AccumulateContext::new(machine, service, &inputs, &mut Storage(&mut self.state))
                .try_run()
                .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt);
        self.agent.restore(invocation);
        self.version += 1;
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
    let agent = agent();
    let counter = actor("counter");
    let ledger = actor("ledger");
    let increment = method(&counter, "increment");
    let ops = method(&counter, "ops");
    let total = method(&ledger, "total");
    // `loop <interpreter|jit> <empty|increments> <n>`: repeat, for profiling.
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
        let node = Node::new(backend, &agent, &counter, &ledger);
        let inputs = match what.as_str() {
            "empty" => Vec::new(),
            "split" => {
                // Where an empty refine's time goes: loading the agent's
                // machine, and running it.
                let work = Work::Batch(Batch {
                    version: node.version,
                    time: 1,
                    seed: [0; 32],
                    budget: GAS,
                    inputs: Vec::new(),
                });
                let arguments = RefineArgs {
                    core: 0,
                    item: 0,
                    service: u64::from(AGENT.0),
                    payload: work.encode(),
                    package_hash: [0; 32],
                }
                .encode();
                let (mut load, mut total) = (Vec::new(), Vec::new());
                for _ in 0..count.parse::<usize>().unwrap() {
                    let started = Instant::now();
                    let context = RefineContext::new(node.agent.load(0, &arguments, GAS).unwrap())
                        .with_pool(Arc::clone(&node.pool))
                        .with_state(Arc::new(Snapshot(node.state.clone())));
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
        let node = Node::new(backend, &agent, &counter, &ledger);
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
    }
}
