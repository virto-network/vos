//! A node's refine and accumulate hosts around the default agent, the test
//! actors installed in it and in a testkit, and what the tests read of a
//! batch's steps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use vos_pvm::accumulate_host::AccumulateContext;
use vos_pvm::pool::{CodeHash, MachinePool};
use vos_pvm::refine::{Invocation, MemoryModel, PreparedProgram};
use vos_pvm::refine_host::{JamItem, JamRefine, Preimages, ProgramSource, RefineContext};
use vos_pvm::{ExitReason, PvmBackend};
use vos_testkit::node::serve;
use vos_testkit::programs::{actor, agent, bare, derivation, derived, kernel, method, package};
use vos_testkit::{Step as KitStep, Testkit, decode};
use vos_wire::abi::cap::Target;
use vos_wire::abi::{Failure, Refusal, cap};
use vos_wire::batch::{Admin, Batch, Input, Query, Request, Work};
use vos_wire::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
};
use vos_wire::ingress::Grant;
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::records::{Installed, SessionMark, unstored};
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::{Decode, Encode, keys};

pub const AGENT: AgentId = AgentId(7);
pub const COUNTER: InstanceId = InstanceId(1);
pub const LEDGER: InstanceId = InstanceId(2);
pub const CALLER: InstanceId = InstanceId(3);
pub const SHOP: InstanceId = InstanceId(4);
pub const ALICE: Principal = Principal::Client([1; 32]);
pub const BOB: Principal = Principal::Client([2; 32]);
pub const MINTER: u8 = 1;
pub const OUTER_GAS: u64 = 4_000_000_000;

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
    programs: Arc<HashMap<[u8; 32], Vec<u8>>>,
    scope: Option<Arc<BTreeSet<[u8; 32]>>>,
}

impl Preimages for Scope {
    fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let scoped = self.scope.as_ref().is_none_or(|scope| scope.contains(hash));
        (service == u64::from(AGENT.0) && scoped)
            .then(|| self.programs.get(hash).cloned())
            .flatten()
    }
}

/// A node's view of one agent: its program, the pool, programs by hash and
/// the agent's storage.
pub struct Node {
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

impl Node {
    pub fn new() -> Self {
        Self::with(true, true)
    }

    /// A VOS node's host, with or without a pool and applied state. With
    /// neither it is a JAM node's, which computes no precompile.
    pub fn with(pool: bool, serves_state: bool) -> Self {
        // Preparing the agent takes most of a test's setup: once a run.
        static AGENT: std::sync::OnceLock<Arc<PreparedProgram>> = std::sync::OnceLock::new();
        let program = AGENT.get_or_init(|| Arc::new(PreparedProgram::new(&agent()).unwrap()));
        Self {
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
    /// package's witness gives it.
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
            programs: Arc::clone(&self.programs),
            scope: None,
        })
    }

    /// What a JAM node gives a refine of `payload`, the agent's preimages
    /// those in `scope` when it is given.
    fn jam_refine(&self, payload: Vec<u8>, scope: Option<Arc<BTreeSet<[u8; 32]>>>) -> JamRefine {
        JamRefine {
            service: u64::from(AGENT.0),
            items: vec![JamItem {
                payload,
                ..JamItem::default()
            }],
            preimages: Some(Arc::new(Scope {
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
        self.budgeted_work(time, seed, OUTER_GAS, inputs)
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
        self.refine_with(work, OUTER_GAS)
    }

    pub fn refine_with(&self, work: &Work, gas: u64) -> Vec<u8> {
        let invocation = self.run_refine(work, gas);
        assert_eq!(invocation.exit, ExitReason::Halt, "refine halts");
        invocation.output_bounded(cap::OUTPUT).unwrap()
    }

    /// The refine's arguments for `work`, as the node passes them.
    pub fn arguments(&self, work: &Work) -> Vec<u8> {
        RefineArgs::new(u64::from(AGENT.0), work.encode(), [0; 32]).encode()
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
            return context.try_run_jam(jam).unwrap().invocation;
        }
        if !self.precompiles {
            context = context.without_precompiles();
        }
        context
            .try_run_with_host(|id, machine| {
                serve(id, machine, AGENT, |hash| {
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
        let mut context = RefineContext::load_with_backend(
            program,
            arguments,
            OUTER_GAS,
            MemoryModel::Auto,
            backend,
        )
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
                serve(id, machine, AGENT, |hash| self.programs.get(hash))
            })
            .unwrap()
    }

    /// The gas a refine of `inputs` at time 1 spends beyond its steps'
    /// gas, which holds what they run and what they are charged: the
    /// agent's own work, less what the charges cover of it. Every step
    /// runs to `Done`.
    pub fn agent_gas(&self, inputs: Vec<Input>) -> i64 {
        let invocation = self.run_refine(&self.work(1, inputs), OUTER_GAS);
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
            u64::from(AGENT.0),
            &inputs,
            OUTER_GAS,
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

    /// A sweep of the rows of the due index due at `time`, as a leader
    /// lists them: the earliest first, at most `SWEEP_LIMIT`.
    pub fn sweep(&self, time: u64) -> Input {
        let prefix = keys::due_prefix();
        let due = self
            .state
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter_map(|(key, _)| keys::due_entry(key))
            .take_while(|(at, _)| *at <= time)
            .take(vos_wire::defaults::SWEEP_LIMIT)
            .collect();
        Input::Sweep { due }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state
            .get(key)
            .map(|bytes| unstored(bytes).expect("a stored value").to_vec())
    }

    pub fn value<T: Decode>(&self, key: &[u8]) -> Option<T> {
        self.get(key).map(|bytes| decode(&bytes).expect("decodes"))
    }

    /// A session's id and mark, as accumulate keeps them.
    pub fn session(&self, session: &Session) -> Option<(SessionId, SessionMark)> {
        let id: SessionId = self.value(&keys::session_index(session))?;
        Some((id, self.value(&keys::session(id)).expect("a mark")))
    }
}

/// The test actors, installed in a node and a testkit alike, and the
/// ledger's attestable's kernel, derived from its ELF.
pub struct Actors {
    pub counter: Vec<u8>,
    pub ledger: Vec<u8>,
    pub caller: Vec<u8>,
    pub checksum: Vec<u8>,
}

impl Actors {
    pub fn load() -> Self {
        Self {
            counter: actor("counter"),
            ledger: actor("ledger"),
            caller: actor("caller"),
            checksum: kernel("ledger", "checksum"),
        }
    }

    /// The ledger's install in `node`, which stores its programs: its own,
    /// which holds its workflow, and its attestable's kernel.
    pub fn install_ledger(&self, node: &mut Node) -> Input {
        self.install_ledger_for(Target::Vos, node)
    }

    /// [`Actors::install_ledger`] for `target`.
    pub fn install_ledger_for(&self, target: Target, node: &mut Node) -> Input {
        node.add(&self.ledger);
        node.add(&self.checksum);
        Input::Admin(Admin::Install {
            instance: LEDGER,
            derivation: derivation(&package("ledger"), &derived("ledger")),
            roles: vec![(b"minter".to_vec(), MINTER)],
            target,
            space: vos_wire::SpaceId::NONE,
            clock: vos_wire::WindowClock::DEFAULT,
        })
    }

    /// The ledger's install in a testkit, for `target`.
    pub fn install_ledger_in_for(&self, target: Target, kit: &mut Testkit) {
        let checksum = method(&self.ledger, "checksum");
        kit.install_for(
            target,
            LEDGER,
            &self.ledger,
            &[(checksum, &self.checksum)],
            &[("minter", MINTER)],
        )
        .unwrap();
    }

    pub fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        let program = match instance {
            COUNTER => &self.counter,
            LEDGER => &self.ledger,
            _ => &self.caller,
        };
        method(program, name)
    }

    /// Install the actors and make Alice a minter, in the node through a
    /// batch of admin inputs and in the testkit directly.
    pub fn install(&self, node: &mut Node, kit: &mut Testkit) {
        self.install_for(Target::Vos, node, kit);
    }

    /// [`Actors::install`] for `target`.
    pub fn install_for(&self, target: Target, node: &mut Node, kit: &mut Testkit) {
        let counter = node.add(&self.counter);
        let caller = node.add(&self.caller);
        let ledger = self.install_ledger_for(target, node);
        let result = node.batch(
            0,
            vec![
                install_for(target, COUNTER, counter),
                ledger,
                install_for(target, CALLER, caller),
                Input::Admin(Admin::SetRole(Grant {
                    principal: ALICE,
                    role: Some(MINTER),
                })),
            ],
        );
        for step in &result.steps {
            ran_done(step);
        }
        kit.install_for(target, COUNTER, &self.counter, &[], &[])
            .unwrap();
        self.install_ledger_in_for(target, kit);
        kit.install_for(target, CALLER, &self.caller, &[], &[])
            .unwrap();
        kit.set_role(ALICE, Some(MINTER));
    }
}

/// Requests in one session per caller, numbered in order.
pub struct Sessions(BTreeMap<Principal, u64>);

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

/// A request incrementing the counter by one, in `session` at `sequence`,
/// from the session's key.
pub fn increment_in(actors: &Actors, session: Session, sequence: u64) -> Input {
    Input::Request(Request {
        session,
        sequence,
        caller: Principal::Client(session.key),
        instance: COUNTER,
        method: actors.method(COUNTER, "increment"),
        arguments: 1u64.encode(),
    })
}

/// An install of `program` at `instance`, with no attestable and no role.
pub fn install(instance: InstanceId, program: ProgramHash) -> Input {
    install_for(Target::Vos, instance, program)
}

/// [`install`] for `target`.
pub fn install_for(target: Target, instance: InstanceId, program: ProgramHash) -> Input {
    Input::Admin(Admin::Install {
        instance,
        derivation: bare(program),
        roles: vec![],
        target,
        space: vos_wire::SpaceId::NONE,
        clock: vos_wire::WindowClock::DEFAULT,
    })
}

/// The step refine gives accumulate for a request in `session` at
/// `sequence` that ran to `Done` with `writes`, and nothing else.
pub fn ran_step(session: SessionRef, sequence: u64, writes: Vec<Write>) -> Step {
    Step::Ran(Run {
        input: InputRef::Request { session, sequence },
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes,
        committed: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        pages: Vec::new(),
        gas_used: 0,
    })
}

pub fn setup() -> (Actors, Node, Testkit, Sessions) {
    let actors = Actors::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    actors.install(&mut node, &mut kit);
    kit.version = node.version;
    (actors, node, kit, Sessions::new())
}

/// `node` with the counter alone installed.
pub fn counter_only(mut node: Node) -> (Actors, Node) {
    let actors = Actors::load();
    let program = node.add(&actors.counter);
    let result = node.batch(0, vec![install(COUNTER, program)]);
    ran(&result.steps[0]);
    (actors, node)
}

/// A step of the node's and the model's agree, field by field.
pub fn agrees(index: usize, run: &Run, expected: &KitStep) {
    assert_eq!(run.outcome, expected.outcome, "step {index}'s outcome");
    assert_eq!(run.writes, expected.writes, "step {index}'s writes");
    assert_eq!(run.committed, expected.committed, "step {index}'s commits");
    assert_eq!(run.messages, expected.messages, "step {index}'s messages");
    assert_eq!(run.attests, expected.attests, "step {index}'s attests");
    assert_eq!(run.pages, expected.pages, "step {index}'s pages");
    assert_eq!(run.instances, expected.instances, "step {index}'s gas");
    assert_eq!(run.gas_used, expected.gas_used, "step {index}'s gas");
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
        Outcome::Done(bytes) => decode(bytes).expect("decodes"),
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
