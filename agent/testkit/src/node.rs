//! The default agent as a VOS node runs it, for the tests and benches:
//! [`Node`], a node's refine and accumulate hosts around the agent's
//! program over one agent's state, the requests of a session per caller
//! ([`Sessions`]) and what a test reads of a batch's steps; and [`serve`],
//! what a VOS node serves the agent beyond the runtime's host.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use vos_abi::abi::surface::LOST;
use vos_abi::abi::{Failure, Refusal, cap, code};
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId};
use vos_abi::jam::{AccumulateInput, Operand, RefineArgs};
use vos_abi::records::{DeviceRelease, Installed, SessionMark, unstored};
use vos_abi::result::{Outcome, Run, Step, WorkResult};
use vos_abi::{Decode, Encode, keys};
use vos_pvm::accumulate_host::AccumulateContext;
use vos_pvm::inner::gp_call::HISTORICAL_LOOKUP;
use vos_pvm::pool::{CodeHash, MachinePool};
use vos_pvm::refine::{Invocation, Machine, MemoryModel, PreparedProgram};
use vos_pvm::refine_host::{
    JamItem, JamRefine, Preimages, ProgramSource, RefineContext, serve_lookup,
};
use vos_pvm::{ExitReason, PvmBackend};
use vos_wire::batch::{Batch, Input, Query, Request, Work};

use crate::programs::agent;

/// The id of the agent a [`Node`] runs when a test names none.
pub const AGENT: AgentId = AgentId(7);
/// The gas of a refine and of an accumulate, and a batch's budget.
pub const GAS: u64 = 4_000_000_000;

/// Serve `agent`'s host call `id` as a VOS node does beyond the runtime:
/// `historical_lookup` from the programs `find` gives ([`serve_lookup`]),
/// and the agent's report of lost state, which stops the refine. Every
/// other call answers `WHAT`.
pub fn serve<P: AsRef<[u8]>>(
    id: u64,
    machine: &mut Machine,
    agent: AgentId,
    find: impl FnOnce(&[u8; 32]) -> Option<P>,
) -> Result<(), ExitReason> {
    match id {
        LOST => Err(ExitReason::HostCall(LOST)),
        id if id == u64::from(HISTORICAL_LOOKUP) => serve_lookup(machine, u64::from(agent.0), find),
        _ => {
            machine.registers_mut()[7] = code::WHAT;
            Ok(())
        }
    }
}

/// A VOS node's program source: the node's programs in the agent's scope.
struct Scoped {
    programs: Arc<HashMap<[u8; 32], Vec<u8>>>,
    scope: Arc<BTreeSet<[u8; 32]>>,
}

impl ProgramSource for Scoped {
    fn owns(&self, hash: &CodeHash) -> bool {
        self.scope.contains(&hash.0)
    }

    fn program(&self, hash: &CodeHash) -> Option<Vec<u8>> {
        self.programs
            .get(&hash.0)
            .filter(|_| self.owns(hash))
            .cloned()
    }
}

/// The agent's preimages on a JAM node: the node's programs, those in
/// `scope` when it is given, of the agent's own service alone.
struct Scope {
    agent: AgentId,
    programs: Arc<HashMap<[u8; 32], Vec<u8>>>,
    scope: Option<Arc<BTreeSet<[u8; 32]>>>,
}

impl Preimages for Scope {
    fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let scoped = self.scope.as_ref().is_none_or(|scope| scope.contains(hash));
        (service == u64::from(self.agent.0) && scoped)
            .then(|| self.programs.get(hash).cloned())
            .flatten()
    }
}

/// A node's view of one agent: its program, the pool, programs by hash and
/// the agent's storage.
pub struct Node {
    /// The agent's id: its service's.
    agent: AgentId,
    /// The agent, prepared once for every refine and accumulate.
    program: Arc<PreparedProgram>,
    /// `None` leaves the loader to build every machine, as on a JAM node.
    pool: Option<Arc<MachinePool>>,
    /// Whether refine may read applied state; a JAM node cannot until
    /// witnesses.
    serves_state: bool,
    /// Whether the host computes the agent's precompiles; a JAM node does
    /// not.
    precompiles: bool,
    /// Whether the host is a JAM node's: the runtime's JAM-only host.
    jam: bool,
    programs: Arc<HashMap<[u8; 32], Vec<u8>>>,
    pub state: BTreeMap<Vec<u8>, Vec<u8>>,
    pub version: u64,
}

impl Default for Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Node {
    pub fn new() -> Self {
        Self::with(true, true)
    }

    /// [`Node::new`] for the agent whose id is `agent`.
    pub fn of(agent: AgentId) -> Self {
        Self {
            agent,
            ..Self::new()
        }
    }

    /// A VOS node's host, with or without a pool and applied state. With
    /// neither it is a JAM node's, which computes no precompile.
    pub fn with(pool: bool, serves_state: bool) -> Self {
        // Preparing the agent takes most of a test's setup: once a run.
        static PREPARED: std::sync::OnceLock<Arc<PreparedProgram>> = std::sync::OnceLock::new();
        let program = PREPARED.get_or_init(|| Arc::new(PreparedProgram::new(&agent()).unwrap()));
        Self {
            agent: AGENT,
            program: Arc::clone(program),
            pool: pool.then(|| Arc::new(MachinePool::new())),
            serves_state,
            precompiles: pool || serves_state,
            jam: false,
            programs: Arc::default(),
            state: BTreeMap::new(),
            version: 0,
        }
    }

    /// A VOS node's host whose agent and inner machines run on `backend`.
    pub fn on(backend: PvmBackend) -> Self {
        static AGENTS: std::sync::Mutex<Vec<(PvmBackend, Arc<PreparedProgram>)>> =
            std::sync::Mutex::new(Vec::new());
        let mut agents = AGENTS.lock().unwrap();
        let program = match agents.iter().find(|(prepared, _)| *prepared == backend) {
            Some((_, program)) => Arc::clone(program),
            None => {
                let program =
                    Arc::new(PreparedProgram::new_with_backend(&agent(), backend).unwrap());
                agents.push((backend, Arc::clone(&program)));
                program
            }
        };
        Self {
            program,
            ..Self::new()
        }
    }

    /// The backends a test runs on: the interpreter, and the recompiler
    /// where it runs.
    pub fn backends() -> Vec<PvmBackend> {
        let mut backends = vec![PvmBackend::ForceInterpreter];
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        backends.push(PvmBackend::ForceRecompiler);
        backends
    }

    /// A JAM node's host, the runtime's JAM-only host: no pool, no
    /// precompile computed, PolkaJam's prices, and the agent's programs as
    /// its preimages. With `serves_state`, it reads applied state as a
    /// package's witness gives it, on the host's state stand-in.
    pub fn jam(serves_state: bool) -> Self {
        Self {
            precompiles: false,
            jam: true,
            ..Self::with(false, serves_state)
        }
    }

    /// The agent's program, prepared.
    pub fn program(&self) -> Arc<PreparedProgram> {
        Arc::clone(&self.program)
    }

    /// The agent's preimages on a JAM node: every program this node holds.
    pub fn preimages(&self) -> Arc<dyn Preimages> {
        Arc::new(Scope {
            agent: self.agent,
            programs: Arc::clone(&self.programs),
            scope: None,
        })
    }

    /// What a JAM node gives a refine of `payload`, the agent's preimages
    /// those in `scope` when it is given.
    fn jam_refine(&self, payload: Vec<u8>, scope: Option<Arc<BTreeSet<[u8; 32]>>>) -> JamRefine {
        JamRefine {
            service: u64::from(self.agent.0),
            items: vec![JamItem {
                payload,
                service: self.agent.0,
                ..JamItem::default()
            }],
            preimages: Some(Arc::new(Scope {
                agent: self.agent,
                programs: Arc::clone(&self.programs),
                scope,
            })),
            ..JamRefine::default()
        }
    }

    /// Lose the program `hash` names, as a node whose store lost it: its
    /// bytes, to add again.
    pub fn forget(&mut self, hash: &ProgramHash) -> Vec<u8> {
        if let Some(pool) = &self.pool {
            pool.uninstall(&vos_pvm::pool::CodeHash(hash.0));
        }
        Arc::make_mut(&mut self.programs)
            .remove(&hash.0)
            .expect("a program the node holds")
    }

    pub fn add(&mut self, blob: &[u8]) -> ProgramHash {
        let hash = ProgramHash::of(blob);
        if let Some(pool) = &self.pool {
            assert_eq!(pool.install(blob).unwrap().0, hash.0);
        }
        Arc::make_mut(&mut self.programs).insert(hash.0, blob.to_vec());
        hash
    }

    /// A batch of `inputs` at `time`, at the agent's next version, its seed
    /// all zeros.
    pub fn work(&self, time: u64, inputs: Vec<Input>) -> Work {
        self.seeded_work(time, [0; 32], inputs)
    }

    /// A batch of `inputs` at `time`, at the agent's next version, seeded
    /// with `seed`.
    pub fn seeded_work(&self, time: u64, seed: [u8; 32], inputs: Vec<Input>) -> Work {
        self.budgeted_work(time, seed, GAS, inputs)
    }

    /// [`Node::seeded_work`] with a budget of `budget`.
    pub fn budgeted_work(
        &self,
        time: u64,
        seed: [u8; 32],
        budget: u64,
        inputs: Vec<Input>,
    ) -> Work {
        Work::Batch(Batch {
            version: self.version,
            time,
            seed,
            budget,
            inputs,
        })
    }

    pub fn refine(&self, work: &Work) -> Vec<u8> {
        self.refine_with(work, GAS)
    }

    pub fn refine_with(&self, work: &Work, gas: u64) -> Vec<u8> {
        let invocation = self.run_refine(work, gas);
        assert_eq!(invocation.exit, ExitReason::Halt, "refine halts");
        invocation.output_bounded(cap::OUTPUT).unwrap()
    }

    /// The refine's arguments for `work`, as the node passes them.
    pub fn arguments(&self, work: &Work) -> Vec<u8> {
        RefineArgs::new(u64::from(self.agent.0), work.encode(), [0; 32]).encode()
    }

    /// Refine `work` with `gas` and, as a node gives it, what decoding a
    /// batch may take beyond it.
    pub fn run_refine(&self, work: &Work, gas: u64) -> Invocation {
        let arguments = self.arguments(work);
        let gas = match work.batch() {
            Some(batch) => gas + vos_wire::defaults::batch_start(batch, arguments.len()),
            None => gas,
        };
        let mut context =
            RefineContext::load_prepared(&self.program, &arguments, gas, MemoryModel::Auto)
                .unwrap();
        let scope = Arc::new(self.scope(work));
        if let Some(pool) = &self.pool {
            context = context
                .with_pool(Arc::clone(pool))
                .with_programs(Arc::new(Scoped {
                    programs: Arc::clone(&self.programs),
                    scope: Arc::clone(&scope),
                }));
        }
        if self.serves_state {
            context = context.with_state(Arc::new(self.state.clone()));
        }
        if self.jam {
            let jam = self.jam_refine(work.encode(), Some(scope));
            let run = if self.serves_state {
                context.try_run_jam_with_state_stand_in(jam)
            } else {
                context.try_run_jam(jam)
            };
            return run.unwrap().invocation;
        }
        if !self.precompiles {
            context = context.without_precompiles();
        }
        context
            .try_run_with_host(|id, machine| {
                serve(id, machine, self.agent, |hash| {
                    self.programs.get(hash).filter(|_| scope.contains(hash))
                })
            })
            .unwrap()
    }

    /// The programs the agent may load in `work`, as a node scopes them:
    /// those its state pins, its installed instances' and its living
    /// workflows', and those `work` installs.
    fn scope(&self, work: &Work) -> BTreeSet<[u8; 32]> {
        let rows = |prefix: Vec<u8>| {
            self.state
                .range(prefix.clone()..)
                .take_while(move |(key, _)| key.starts_with(&prefix))
        };
        let mut scope: BTreeSet<[u8; 32]> = rows(keys::installed_prefix())
            .filter_map(|(_, value)| Installed::decode(unstored(value)?).ok())
            .flat_map(|(installed, _)| installed.programs().collect::<Vec<_>>())
            .chain(
                rows(keys::workflow_pins_prefix())
                    .filter_map(|(key, _)| keys::workflow_pins_entry(key)),
            )
            .map(|program| program.0)
            .collect();
        if let Some(batch) = work.batch() {
            scope.extend(batch.installs().map(|program| program.0));
        }
        scope
    }

    /// Run `program`, an outer program like the agent, on `arguments` with
    /// this node's host and `backend`.
    pub fn run_outer(&self, program: &[u8], arguments: &[u8], backend: PvmBackend) -> Invocation {
        let mut context =
            RefineContext::load_with_backend(program, arguments, GAS, MemoryModel::Auto, backend)
                .unwrap();
        if let Some(pool) = &self.pool {
            context = context.with_pool(Arc::clone(pool));
        }
        if self.jam {
            let jam = self.jam_refine(Vec::new(), None);
            return context.try_run_jam(jam).unwrap().invocation;
        }
        if !self.precompiles {
            context = context.without_precompiles();
        }
        context
            .try_run_with_host(|id, machine| {
                serve(id, machine, self.agent, |hash| self.programs.get(hash))
            })
            .unwrap()
    }

    /// The gas a refine of `inputs` at time 1 spends beyond its steps'
    /// gas, which holds what they run and what they are charged: the
    /// agent's own work, less what the charges cover of it. Every step
    /// runs to `Done`.
    pub fn agent_gas(&self, inputs: Vec<Input>) -> i64 {
        let invocation = self.run_refine(&self.work(1, inputs), GAS);
        assert_eq!(invocation.exit, ExitReason::Halt, "refine halts");
        let (result, _) =
            WorkResult::decode(&invocation.output_bounded(cap::OUTPUT).unwrap()).unwrap();
        let steps: u64 = result
            .steps
            .iter()
            .map(|step| ran_done(step).gas_used)
            .sum();
        invocation.gas_used as i64 - steps as i64
    }

    pub fn accumulate(&mut self, result: &[u8]) {
        let inputs = [AccumulateInput::Operand(Operand::new(result.to_vec())).encode()];
        let invocation = AccumulateContext::load(
            &self.program,
            0,
            u64::from(self.agent.0),
            &inputs,
            GAS,
            &mut self.state,
        )
        .unwrap()
        .try_run()
        .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt, "accumulate halts");
    }

    /// A batch of `inputs` at `time`, its seed all zeros, refined and
    /// accumulated: its work result.
    pub fn batch(&mut self, time: u64, inputs: Vec<Input>) -> WorkResult {
        self.apply(&self.work(time, inputs))
    }

    /// `work` refined and accumulated: its work result.
    pub fn apply(&mut self, work: &Work) -> WorkResult {
        let bytes = self.refine(work);
        self.accumulate(&bytes);
        self.version += 1;
        WorkResult::decode(&bytes).unwrap().0
    }

    pub fn query(
        &self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Outcome {
        let work = Work::Query(Query {
            time: 0,
            seed: [0; 32],
            caller,
            instance,
            method,
            arguments,
        });
        Outcome::decode(&self.refine(&work)).unwrap().0
    }

    /// A sweep of the rows of the due indexes due at `time`, as a leader
    /// lists them: the earliest first, within a sweep's budget.
    pub fn sweep(&self, time: u64) -> Input {
        let scan = |index: keys::DueIndex| {
            self.state
                .range(index.prefix().to_vec()..)
                .map(|(key, _)| Ok::<_, ()>(key))
        };
        let due = keys::sweep_rows(scan, time, vos_wire::defaults::SWEEP_LIMIT).unwrap();
        Input::Sweep { due }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state
            .get(key)
            .map(|bytes| unstored(bytes).expect("a stored value").to_vec())
    }

    pub fn value<T: Decode>(&self, key: &[u8]) -> Option<T> {
        self.get(key)
            .map(|bytes| crate::model::decode(&bytes).expect("decodes"))
    }

    /// The release of `instance`'s device kernel `kernel` an install put
    /// there, which ingress verifies a proof against; zeros for an
    /// instance not installed or a method that is no device kernel.
    pub fn release(&self, instance: InstanceId, kernel: MethodId) -> DeviceRelease {
        self.value::<Installed>(&keys::installed(instance))
            .and_then(|installed| installed.derivation.device(kernel))
            .unwrap_or(DeviceRelease {
                kernel: ProgramHash([0; 32]),
                reference: ProgramHash([0; 32]),
                headroom: 0,
            })
    }

    /// A session's id and mark, as accumulate keeps them.
    pub fn session(&self, session: &Session) -> Option<(SessionId, SessionMark)> {
        let id: SessionId = self.value(&keys::session_index(session))?;
        Some((id, self.value(&keys::session(id)).expect("a mark")))
    }
}

/// Requests in one session per caller, numbered in order.
pub struct Sessions(BTreeMap<Principal, u64>);

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl Sessions {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn session(caller: &Principal) -> Session {
        Session {
            key: match caller {
                Principal::Client(key) => *key,
                _ => [0; 32],
            },
            name: [0; 16],
            t0: 0,
        }
    }

    pub fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        self.request_bytes(caller, instance, method, arguments.encode())
    }

    /// [`Sessions::request`] with its arguments already encoded.
    pub fn request_bytes(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Input {
        let sequence = self.0.entry(caller).or_insert(0);
        *sequence += 1;
        request(caller, *sequence, instance, method, arguments)
    }
}

/// `caller`'s request at `sequence` of its session in [`Sessions`].
pub fn request(
    caller: Principal,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: Vec<u8>,
) -> Input {
    Input::Request(Request {
        session: Sessions::session(&caller),
        sequence,
        caller,
        instance,
        method,
        arguments,
    })
}

pub fn ran(step: &Step) -> &Run {
    match step {
        Step::Ran(run) => run,
        other => panic!("did not run: {other:?}"),
    }
}

/// The run of a step that ran to `Done`.
pub fn ran_done(step: &Step) -> &Run {
    let run = ran(step);
    assert!(
        matches!(run.outcome, Outcome::Done(_)),
        "failed: {:?}",
        run.outcome
    );
    run
}

pub fn done<T: Decode>(step: &Step) -> T {
    match &ran(step).outcome {
        Outcome::Done(bytes) => crate::model::decode(bytes).expect("decodes"),
        other => panic!("failed: {other:?}"),
    }
}

pub fn failed(step: &Step) -> Failure {
    match &ran(step).outcome {
        Outcome::Failed { code, .. } => *code,
        other => panic!("done: {other:?}"),
    }
}

pub fn refused(step: &Step) -> Refusal {
    match step {
        Step::Refused { code, .. } => *code,
        other => panic!("not refused: {other:?}"),
    }
}
