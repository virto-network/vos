//! The default agent (`agent/default`, built by `just build-agent`) on the
//! node's refine and accumulate hosts, step by step against the testkit.
//! The tests fail, not skip, when the programs are missing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use proptest::prelude::*;
use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{AccumulateContext, ServiceStorage};
use vos_pvm::pool::MachinePool;
use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
use vos_pvm::refine_host::{RefineContext, StateReader};
use vos_testkit::programs::{actor, agent, method};
use vos_testkit::{Testkit, decode, program_hash};
use vos_wire::abi::{cap, code, failure, refusal};
use vos_wire::batch::{Admin, Batch, Input, Query, Request, Work};
use vos_wire::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::records::{SessionMark, stored, unstored};
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, expiry, keys};

const AGENT: AgentId = AgentId(7);
const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
const CALLER: InstanceId = InstanceId(3);
const ALICE: Principal = Principal::Client([1; 32]);
const BOB: Principal = Principal::Client([2; 32]);
const MINTER: u8 = 1;
const OUTER_GAS: u64 = 4_000_000_000;

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

/// `historical_lookup` from the node's programs; every other call the host
/// does not serve answers `WHAT`.
fn serve(id: u64, machine: &mut Machine, programs: &HashMap<[u8; 32], Vec<u8>>) {
    let registers = *machine.registers();
    if id != 7 {
        machine.registers_mut()[7] = code::WHAT;
        return;
    }
    let mut hash = [0u8; 32];
    assert!(
        machine
            .memory()
            .read_bytes_checked(registers[8] as u32, &mut hash)
    );
    match programs.get(&hash) {
        Some(blob) => {
            let offset = (registers[10] as usize).min(blob.len());
            let len = (registers[11] as usize).min(blob.len() - offset);
            assert!(
                machine
                    .memory_mut()
                    .write_bytes_checked(registers[9] as u32, &blob[offset..offset + len])
            );
            machine.registers_mut()[7] = blob.len() as u64;
        }
        None => machine.registers_mut()[7] = code::NONE,
    }
}

/// A node's view of one agent: its program, the pool, programs by hash and
/// the agent's storage.
struct Node {
    /// The agent, prepared once for every refine and accumulate.
    program: Arc<PreparedProgram>,
    /// `None` leaves the loader to build every machine, as on a JAM node.
    pool: Option<Arc<MachinePool>>,
    /// Whether refine may read applied state; a JAM node cannot until
    /// witnesses.
    serves_state: bool,
    programs: HashMap<[u8; 32], Vec<u8>>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    version: u64,
}

impl Node {
    fn new() -> Self {
        Self::with(true, true)
    }

    fn with(pool: bool, serves_state: bool) -> Self {
        // Preparing the agent takes most of a test's setup: once a run.
        static AGENT: std::sync::OnceLock<Arc<PreparedProgram>> = std::sync::OnceLock::new();
        let program = AGENT.get_or_init(|| Arc::new(PreparedProgram::new(&agent()).unwrap()));
        Self {
            program: Arc::clone(program),
            pool: pool.then(|| Arc::new(MachinePool::new())),
            serves_state,
            programs: HashMap::new(),
            state: BTreeMap::new(),
            version: 0,
        }
    }

    fn add(&mut self, blob: &[u8]) -> ProgramHash {
        let hash = program_hash(blob);
        if let Some(pool) = &self.pool {
            assert_eq!(pool.install(blob).unwrap().0, hash.0);
        }
        self.programs.insert(hash.0, blob.to_vec());
        hash
    }

    fn refine(&self, work: &Work) -> Vec<u8> {
        self.refine_with(work, OUTER_GAS)
    }

    fn refine_with(&self, work: &Work, gas: u64) -> Vec<u8> {
        let invocation = self.run_refine(work, gas);
        assert_eq!(invocation.exit, ExitReason::Halt, "refine halts");
        invocation.output_bounded(cap::WORK_RESULT).unwrap()
    }

    fn run_refine(&self, work: &Work, gas: u64) -> vos_pvm::refine::Invocation {
        let arguments = RefineArgs {
            core: 0,
            item: 0,
            service: u64::from(AGENT.0),
            payload: work.encode(),
            package_hash: [0; 32],
        }
        .encode();
        let mut context =
            RefineContext::load_prepared(&self.program, &arguments, gas, MemoryModel::Auto)
                .unwrap();
        if let Some(pool) = &self.pool {
            context = context.with_pool(Arc::clone(pool));
        }
        if self.serves_state {
            context = context.with_state(Arc::new(Snapshot(self.state.clone())));
        }
        if self.pool.is_none() && !self.serves_state {
            // A JAM node: no pool, no state, and no precompile computed.
            context = context.without_precompiles();
        }
        context
            .try_run_with_host(|id, machine| {
                serve(id, machine, &self.programs);
                Ok(())
            })
            .unwrap()
    }

    fn accumulate(&mut self, result: &[u8]) {
        let input = AccumulateInput::Operand(Operand {
            package_hash: [0; 32],
            segment_root: [0; 32],
            authorizer: [0; 32],
            payload_hash: [0; 32],
            gas_limit: 0,
            result: Ok(result.to_vec()),
            auth_trace: Vec::new(),
        })
        .encode();
        let inputs = [input];
        let invocation = AccumulateContext::load(
            &self.program,
            0,
            u64::from(AGENT.0),
            &inputs,
            OUTER_GAS,
            &mut Storage(&mut self.state),
        )
        .unwrap()
        .try_run()
        .unwrap();
        assert_eq!(invocation.exit, ExitReason::Halt, "accumulate halts");
    }

    fn batch(&mut self, time: u64, seed: [u8; 32], inputs: Vec<Input>) -> WorkResult {
        self.batch_with(time, seed, inputs, OUTER_GAS)
    }

    fn batch_with(
        &mut self,
        time: u64,
        seed: [u8; 32],
        inputs: Vec<Input>,
        gas: u64,
    ) -> WorkResult {
        let work = Work::Batch(Batch {
            version: self.version,
            time,
            seed,
            inputs,
        });
        let bytes = self.refine_with(&work, gas);
        self.accumulate(&bytes);
        self.version += 1;
        WorkResult::decode(&bytes).unwrap().0
    }

    fn query(
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

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state
            .get(key)
            .map(|bytes| unstored(bytes).expect("a stored value").to_vec())
    }

    fn value<T: Decode>(&self, key: &[u8]) -> Option<T> {
        self.get(key).map(|bytes| decode(&bytes).expect("decodes"))
    }

    /// A session's id and mark, as accumulate keeps them.
    fn session(&self, session: &Session) -> Option<(SessionId, SessionMark)> {
        let id: SessionId = self.value(&keys::session_index(session))?;
        Some((id, self.value(&keys::session(id)).expect("a mark")))
    }
}

/// The test actors, installed in a node and a testkit alike.
struct Programs {
    counter: Vec<u8>,
    ledger: Vec<u8>,
    caller: Vec<u8>,
    checksum: Vec<u8>,
}

impl Programs {
    fn load() -> Self {
        Self {
            counter: actor("counter"),
            ledger: actor("ledger"),
            caller: actor("caller"),
            checksum: actor("checksum"),
        }
    }

    fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        let program = match instance {
            COUNTER => &self.counter,
            LEDGER => &self.ledger,
            _ => &self.caller,
        };
        method(program, name)
    }

    /// Install the actors and make Alice a minter, in the node through a
    /// batch of admin inputs and in the testkit directly.
    fn install(&self, node: &mut Node, kit: &mut Testkit) {
        let counter = node.add(&self.counter);
        let ledger = node.add(&self.ledger);
        let caller = node.add(&self.caller);
        let checksum = node.add(&self.checksum);
        let audit = method(&self.ledger, "checksum");
        let result = node.batch(
            0,
            [0; 32],
            vec![
                Input::Admin(Admin::Install {
                    instance: COUNTER,
                    program: counter,
                    attestables: vec![],
                    roles: vec![],
                }),
                Input::Admin(Admin::Install {
                    instance: LEDGER,
                    program: ledger,
                    attestables: vec![(audit, checksum)],
                    roles: vec![(b"minter".to_vec(), MINTER)],
                }),
                Input::Admin(Admin::Install {
                    instance: CALLER,
                    program: caller,
                    attestables: vec![],
                    roles: vec![],
                }),
                Input::Admin(Admin::SetRole {
                    principal: ALICE,
                    role: Some(MINTER),
                }),
            ],
        );
        for step in &result.steps {
            assert!(
                matches!(
                    step,
                    Step::Ran(Run {
                        outcome: Outcome::Done(_),
                        ..
                    })
                ),
                "{step:?}"
            );
        }
        kit.install(COUNTER, &self.counter, &[], &[]).unwrap();
        kit.install(
            LEDGER,
            &self.ledger,
            &[(audit, &self.checksum)],
            &[("minter", MINTER)],
        )
        .unwrap();
        kit.install(CALLER, &self.caller, &[], &[]).unwrap();
        kit.set_role(ALICE, Some(MINTER));
    }
}

/// Requests in one session per caller, numbered in order.
struct Sessions(BTreeMap<Principal, u64>);

impl Sessions {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn session(caller: &Principal) -> Session {
        Session {
            key: match caller {
                Principal::Client(key) => *key,
                _ => [0; 32],
            },
            name: [0; 16],
            t0: 0,
        }
    }

    fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        let sequence = self.0.entry(caller).or_insert(0);
        *sequence += 1;
        Input::Request(Request {
            session: Self::session(&caller),
            sequence: *sequence,
            caller,
            instance,
            method,
            arguments: arguments.encode(),
        })
    }
}

fn setup() -> (Programs, Node, Testkit, Sessions) {
    let programs = Programs::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    programs.install(&mut node, &mut kit);
    (programs, node, kit, Sessions::new())
}

fn ran(step: &Step) -> &Run {
    match step {
        Step::Ran(run) => run,
        other => panic!("did not run: {other:?}"),
    }
}

fn done<T: Decode>(step: &Step) -> T {
    match &ran(step).outcome {
        Outcome::Done(bytes) => decode(bytes).expect("decodes"),
        other => panic!("failed: {other:?}"),
    }
}

fn failed(step: &Step) -> u32 {
    match &ran(step).outcome {
        Outcome::Failed { code, .. } => *code,
        other => panic!("done: {other:?}"),
    }
}

#[test]
fn a_failed_step_consumes_its_input_and_later_steps_see_earlier_writes() {
    let (programs, mut node, _, mut sessions) = setup();
    let increment = programs.method(COUNTER, "increment");
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, increment, 5u64),
            sessions.request(ALICE, COUNTER, increment, u64::MAX),
            sessions.request(ALICE, COUNTER, increment, 3u64),
        ],
    );
    assert_eq!(done::<u64>(&result.steps[0]), 5);
    assert_eq!(failed(&result.steps[1]), failure::HANDLER);
    assert!(ran(&result.steps[1]).writes.is_empty());
    assert_eq!(done::<u64>(&result.steps[2]), 8, "the batch overlay");
    let (_, mark) = node.session(&Sessions::session(&ALICE)).unwrap();
    assert_eq!(mark.sequence, 3, "the failed request was consumed too");
    assert_eq!(
        node.query(
            ALICE,
            COUNTER,
            programs.method(COUNTER, "value"),
            ().encode()
        ),
        Outcome::Done(8u64.encode())
    );
}

#[test]
fn sessions_refuse_gaps_and_expiry_and_keep_a_reply_window() {
    let (programs, mut node, _, _) = setup();
    let increment = programs.method(COUNTER, "increment");
    let session = Session {
        key: [9; 32],
        name: [9; 16],
        t0: 1,
    };
    let request = |sequence: u64| {
        Input::Request(Request {
            session,
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: increment,
            arguments: 1u64.encode(),
        })
    };
    let result = node.batch(
        1,
        [0; 32],
        vec![request(2), request(1), request(1), request(2)],
    );
    assert!(matches!(
        result.steps[0],
        Step::Refused {
            code: refusal::SEQUENCE,
            ..
        }
    ));
    assert_eq!(done::<u64>(&result.steps[1]), 1);
    assert!(matches!(
        result.steps[2],
        Step::Refused {
            code: refusal::SEQUENCE,
            ..
        }
    ));
    assert_eq!(done::<u64>(&result.steps[3]), 2);
    let (id, _) = node.session(&session).unwrap();
    assert_eq!(
        node.get(&keys::reply(id, 2)),
        Some(Outcome::Done(2u64.encode()).encode())
    );

    let later = 2 + defaults::SESSION_EXPIRY_MS;
    let result = node.batch(later, [0; 32], vec![request(3)]);
    assert!(matches!(
        result.steps[0],
        Step::Refused {
            code: refusal::EXPIRED,
            ..
        }
    ));
}

/// A session is its key, name and creation time: accumulate gives each a
/// compact id when its first request applies, and a step names a session
/// by that id once the state holds it. A new session must start at 1, near
/// the batch's time.
#[test]
fn sessions_are_named_by_their_client_and_created_by_accumulate() {
    let (programs, mut node, _, _) = setup();
    let increment = programs.method(COUNTER, "increment");
    let now = 1_000_000;
    let session = |name: u8, t0: u64| Session {
        key: [1; 32],
        name: [name; 16],
        t0,
    };
    let (first, second) = (session(1, now), session(2, now - 30_000));
    let stale = session(3, now - defaults::SESSION_SKEW_MS - 1);
    let ahead = session(4, now + defaults::SESSION_SKEW_MS + 1);
    let request = |session: Session, sequence: u64| {
        Input::Request(Request {
            session,
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: increment,
            arguments: 1u64.encode(),
        })
    };
    let result = node.batch(
        now,
        [0; 32],
        vec![
            request(first, 1),
            request(second, 1),
            request(first, 2),
            request(stale, 1),
            request(ahead, 1),
            request(session(5, now), 2),
            request(
                Session {
                    t0: now + 1,
                    ..first
                },
                1,
            ),
        ],
    );
    let named = |step: &Step| match step {
        Step::Ran(Run {
            input: InputRef::Request { session, .. },
            ..
        })
        | Step::Refused {
            input: InputRef::Request { session, .. },
            ..
        } => session.clone(),
        other => panic!("not a request: {other:?}"),
    };
    let code = |step: &Step| match step {
        Step::Refused { code, .. } => *code,
        other => panic!("not refused: {other:?}"),
    };
    assert_eq!(named(&result.steps[0]), SessionRef::New(Box::new(first)));
    assert_eq!(named(&result.steps[2]), SessionRef::New(Box::new(first)));
    assert_eq!(done::<u64>(&result.steps[2]), 3);
    assert_eq!(code(&result.steps[3]), refusal::STALE_SESSION);
    assert_eq!(code(&result.steps[4]), refusal::STALE_SESSION);
    assert_eq!(
        code(&result.steps[5]),
        refusal::SEQUENCE,
        "a new session starts at 1"
    );
    assert_eq!(
        done::<u64>(&result.steps[6]),
        4,
        "another t0 is another session"
    );

    let (one, mark) = node.session(&first).unwrap();
    assert_eq!(
        mark,
        SessionMark {
            sequence: 2,
            time: now
        }
    );
    assert_eq!(node.value::<Session>(&keys::session_of(one)), Some(first));
    let (two, _) = node.session(&second).unwrap();
    assert_ne!(one, two);
    assert_eq!(node.session(&stale), None);
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(3));
    assert_eq!(node.value::<u64>(&keys::next_session()), Some(3));
    assert_eq!(node.value::<u64>(&keys::batch_time()), Some(now));

    let result = node.batch(now + 5, [0; 32], vec![request(first, 3)]);
    assert_eq!(named(&result.steps[0]), SessionRef::Known(one));
    assert_eq!(done::<u64>(&result.steps[0]), 5);
    assert_eq!(node.session(&first).unwrap().1.sequence, 3);
}

/// Accumulate is the authority on time: a result with a new session far
/// from its time, or timed before the agent's latest, applies nothing at
/// all. Refine refuses such a session, so a later step may have been
/// refined as if that one had run.
#[test]
fn accumulate_skips_stale_sessions_and_results_from_the_past() {
    let (_, mut node, _, _) = setup();
    let now = 1_000_000;
    let session = |name: u8, t0: u64| Session {
        key: [2; 32],
        name: [name; 16],
        t0,
    };
    let (fresh, stale) = (session(1, now), session(2, 1));
    let step = |session: SessionRef, key: u8| {
        Step::Ran(Run {
            input: InputRef::Request {
                session,
                sequence: 1,
            },
            outcome: Outcome::Done(Vec::new()),
            instances: Vec::new(),
            writes: vec![Write {
                key: vec![0x01, key],
                value: Some(vec![key]),
            }],
            messages: Vec::new(),
            attests: Vec::new(),
            gas_used: 0,
        })
    };
    let version = node.version;
    let applied = |node: &Node| {
        (
            node.value::<u64>(&keys::version()),
            node.value::<u64>(&keys::batch_time()),
        )
    };
    let before = applied(&node);
    let result = WorkResult {
        version,
        time: now,
        seed: [0; 32],
        steps: vec![
            step(SessionRef::New(Box::new(stale)), 1),
            step(SessionRef::New(Box::new(fresh)), 3),
        ],
    };
    node.accumulate(&result.encode());
    assert_eq!(node.get(&[0x01, 1]), None);
    assert_eq!(node.get(&[0x01, 3]), None);
    assert_eq!(node.session(&stale), None);
    assert_eq!(node.session(&fresh), None);
    assert_eq!(applied(&node), before, "nothing at all");

    let fresh_only = WorkResult {
        steps: vec![step(SessionRef::New(Box::new(fresh)), 3)],
        ..result
    };
    node.accumulate(&fresh_only.encode());
    assert_eq!(node.get(&[0x01, 3]), Some(vec![3]));
    assert_eq!(node.session(&fresh).unwrap().1.sequence, 1);
    assert_eq!(node.value::<u64>(&keys::version()), Some(version + 1));

    let past = WorkResult {
        version: version + 1,
        time: now - 1,
        seed: [0; 32],
        steps: vec![step(SessionRef::New(Box::new(session(3, now))), 4)],
    };
    node.accumulate(&past.encode());
    assert_eq!(node.get(&[0x01, 4]), None);
    assert_eq!(node.value::<u64>(&keys::version()), Some(version + 1));
    assert_eq!(node.value::<u64>(&keys::batch_time()), Some(now));
}

/// A request incrementing the counter by one, in `session` at `sequence`.
fn increment_in(programs: &Programs, session: Session, sequence: u64) -> Input {
    Input::Request(Request {
        session,
        sequence,
        caller: Principal::Client(session.key),
        instance: COUNTER,
        method: programs.method(COUNTER, "increment"),
        arguments: 1u64.encode(),
    })
}

fn refused(step: &Step) -> u32 {
    match step {
        Step::Refused { code, .. } => *code,
        other => panic!("not refused: {other:?}"),
    }
}

fn swept(step: &Step) -> Vec<(u64, SessionId)> {
    match step {
        Step::Swept { due } => due.clone(),
        other => panic!("not a sweep: {other:?}"),
    }
}

/// A session leaves whole once it has expired and its expiry row is due:
/// its index, whole, mark, kept replies, row and counts. A session active
/// since has its row moved instead. Before collection an expired session
/// is refused `EXPIRED`, a duplicate of it `SEQUENCE` (the leader answers
/// it from the window); after, its requests name a stale t0 and never run.
#[test]
fn sessions_are_collected_once_expired_and_moved_while_active() {
    let (programs, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let bucket = expiry::bucket(now);
    let session = |name: u8, t0: u64| Session {
        key: [3; 32],
        name: [name; 16],
        t0,
    };
    let (idle, active) = (session(1, now), session(2, now));
    node.batch(
        now,
        [0; 32],
        vec![
            increment_in(&programs, idle, 1),
            increment_in(&programs, idle, 2),
            increment_in(&programs, active, 1),
        ],
    );
    let (idle_id, _) = node.session(&idle).unwrap();
    let (active_id, _) = node.session(&active).unwrap();
    for id in [idle_id, active_id] {
        assert_eq!(node.get(&keys::expiry(bucket, id)), Some(Vec::new()));
    }
    assert_eq!(node.value::<u64>(&keys::key_sessions(&[3; 32])), Some(2));

    let later = now + defaults::SESSION_EXPIRY_MS / 2;
    node.batch(later, [0; 32], vec![increment_in(&programs, active, 2)]);
    assert_eq!(
        node.get(&keys::expiry(bucket, active_id)),
        Some(Vec::new()),
        "a request does not move its row"
    );

    let due = expiry::due(bucket);
    let result = node.batch(due - 1, [0; 32], vec![Input::Sweep]);
    assert_eq!(swept(&result.steps[0]), Vec::new(), "not due yet");
    let result = node.batch(
        due - 1,
        [0; 32],
        vec![
            increment_in(&programs, idle, 3),
            increment_in(&programs, idle, 2),
        ],
    );
    assert_eq!(refused(&result.steps[0]), refusal::EXPIRED);
    assert_eq!(refused(&result.steps[1]), refusal::SEQUENCE);

    let result = node.batch(due, [0; 32], vec![Input::Sweep]);
    assert_eq!(
        swept(&result.steps[0]),
        vec![(bucket, idle_id), (bucket, active_id)]
    );
    assert_eq!(node.session(&idle), None);
    assert_eq!(node.get(&keys::session_of(idle_id)), None);
    assert_eq!(node.get(&keys::session(idle_id)), None);
    for sequence in 1..=2 {
        assert_eq!(node.get(&keys::reply(idle_id, sequence)), None);
    }
    assert_eq!(node.get(&keys::expiry(bucket, idle_id)), None);
    assert_eq!(node.get(&keys::expiry(bucket, active_id)), None);
    assert_eq!(
        node.get(&keys::expiry(expiry::bucket(later), active_id)),
        Some(Vec::new()),
        "moved to its mark's bucket"
    );
    assert!(node.session(&active).is_some());
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(1));
    assert_eq!(node.value::<u64>(&keys::key_sessions(&[3; 32])), Some(1));

    let result = node.batch(
        due + 1,
        [0; 32],
        vec![
            increment_in(&programs, idle, 3),
            increment_in(&programs, idle, 1),
            increment_in(&programs, session(3, due), 1),
        ],
    );
    assert_eq!(refused(&result.steps[0]), refusal::STALE_SESSION);
    assert_eq!(refused(&result.steps[1]), refusal::STALE_SESSION);
    assert_eq!(done::<u64>(&result.steps[2]), 5, "the collected ran 2");
    assert_eq!(
        node.session(&session(3, due)).unwrap().0,
        SessionId(2),
        "ids are never reused"
    );

    // The moved row comes due in its turn, and the active session goes.
    let due = expiry::due(expiry::bucket(later));
    let result = node.batch(due, [0; 32], vec![Input::Sweep]);
    assert_eq!(
        swept(&result.steps[0]),
        vec![(expiry::bucket(later), active_id)]
    );
    assert_eq!(node.session(&active), None);
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(1));
}

/// The caps refuse a new session, never evict one, counting the sessions
/// a batch creates; collection makes room again, a sweep at a time.
#[test]
fn session_caps_refuse_new_sessions_until_some_are_collected() {
    let (programs, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let one_key = |name: u64| Session {
        key: [4; 32],
        name: u128::from(name).to_le_bytes(),
        t0: now,
    };
    let other = Session {
        key: [5; 32],
        name: [0; 16],
        t0: now,
    };
    let mut inputs: Vec<Input> = (0..=defaults::MAX_KEY_SESSIONS)
        .map(|name| increment_in(&programs, one_key(name), 1))
        .collect();
    inputs.push(increment_in(&programs, other, 1));
    let result = node.batch(now, [0; 32], inputs);
    let cap = defaults::MAX_KEY_SESSIONS as usize;
    for step in &result.steps[..cap] {
        ran(step);
    }
    assert_eq!(refused(&result.steps[cap]), refusal::KEY_SESSIONS_FULL);
    ran(&result.steps[cap + 1]);
    assert_eq!(
        node.value::<u64>(&keys::key_sessions(&[4; 32])),
        Some(defaults::MAX_KEY_SESSIONS)
    );
    let result = node.batch(
        now + 1,
        [0; 32],
        vec![increment_in(&programs, one_key(999), 1)],
    );
    assert_eq!(refused(&result.steps[0]), refusal::KEY_SESSIONS_FULL);

    // The agent's cap, at one session from it.
    let live = cap as u64 + 1;
    node.state.insert(
        keys::live_sessions(),
        stored(&(defaults::MAX_SESSIONS - 1).encode()),
    );
    let fresh = |key: u8| Session {
        key: [key; 32],
        name: [0; 16],
        t0: now,
    };
    let result = node.batch(
        now + 2,
        [0; 32],
        vec![
            increment_in(&programs, fresh(6), 1),
            increment_in(&programs, fresh(7), 1),
            increment_in(&programs, fresh(6), 2),
        ],
    );
    ran(&result.steps[0]);
    assert_eq!(refused(&result.steps[1]), refusal::SESSIONS_FULL);
    ran(&result.steps[2]);
    node.state
        .insert(keys::live_sessions(), stored(&(live + 1).encode()));

    // Past expiry, a sweep at a time, at most `SWEEP_LIMIT` each.
    let due = expiry::due(expiry::bucket(now));
    let mut sweeps = 0;
    loop {
        let result = node.batch(due, [0; 32], vec![Input::Sweep]);
        let listed = swept(&result.steps[0]).len();
        assert!(listed <= defaults::SWEEP_LIMIT);
        if listed == 0 {
            break;
        }
        sweeps += 1;
    }
    assert_eq!(sweeps, (live as usize + 1).div_ceil(defaults::SWEEP_LIMIT));
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(0));
    assert_eq!(node.get(&keys::key_sessions(&[4; 32])), None);
    let result = node.batch(
        due + 1,
        [0; 32],
        vec![increment_in(
            &programs,
            Session {
                t0: due,
                ..one_key(999)
            },
            1,
        )],
    );
    ran(&result.steps[0]);
}

/// Accumulate checks the caps itself, counting each new session once, and
/// takes every row a sweep lists out of the due range, whatever the state
/// holds of its session.
#[test]
fn accumulate_holds_the_caps_and_clears_the_rows_a_sweep_lists() {
    let (_, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let session = |name: u8| Session {
        key: [6; 32],
        name: [name; 16],
        t0: now,
    };
    let step = |session: SessionRef, sequence: u64| {
        Step::Ran(Run {
            input: InputRef::Request { session, sequence },
            outcome: Outcome::Done(Vec::new()),
            instances: Vec::new(),
            writes: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            gas_used: 0,
        })
    };
    let version = |node: &Node| node.value::<u64>(&keys::version()).unwrap_or(0);
    node.state.insert(
        keys::live_sessions(),
        stored(&(defaults::MAX_SESSIONS - 1).encode()),
    );
    let two = WorkResult {
        version: version(&node),
        time: now,
        seed: [0; 32],
        steps: vec![
            step(SessionRef::New(Box::new(session(1))), 1),
            step(SessionRef::New(Box::new(session(2))), 1),
        ],
    };
    let before = version(&node);
    node.accumulate(&two.encode());
    assert_eq!(version(&node), before, "past the agent's cap: nothing");
    assert_eq!(node.session(&session(1)), None);
    let one = WorkResult {
        steps: vec![
            step(SessionRef::New(Box::new(session(1))), 1),
            step(SessionRef::New(Box::new(session(1))), 2),
        ],
        ..two.clone()
    };
    node.accumulate(&one.encode());
    assert_eq!(version(&node), before + 1, "one session, named twice");
    assert_eq!(node.session(&session(1)).unwrap().1.sequence, 2);
    assert_eq!(
        node.value::<u64>(&keys::live_sessions()),
        Some(defaults::MAX_SESSIONS)
    );

    // A row listed early stays; a row without a session goes; a session
    // without its whole loses all the triple does not name.
    let (id, _) = node.session(&session(1)).unwrap();
    let bucket = expiry::bucket(now);
    let orphan = (bucket, SessionId(99));
    node.state
        .insert(keys::expiry(orphan.0, orphan.1), stored(&[]));
    let sweep = |time: u64, version: u64| WorkResult {
        version,
        time,
        seed: [0; 32],
        steps: vec![Step::Swept {
            due: vec![orphan, (bucket, id)],
        }],
    };
    node.accumulate(&sweep(now + 1, version(&node)).encode());
    assert_eq!(node.get(&keys::expiry(orphan.0, orphan.1)), None);
    assert_eq!(node.get(&keys::expiry(bucket, id)), Some(Vec::new()));
    node.state.remove(&keys::session_of(id));
    let due = expiry::due(bucket);
    node.accumulate(&sweep(due, version(&node)).encode());
    assert_eq!(node.get(&keys::session(id)), None);
    assert_eq!(node.get(&keys::reply(id, 1)), None);
    assert_eq!(node.get(&keys::reply(id, 2)), None);
    assert_eq!(node.get(&keys::expiry(bucket, id)), None);
    assert!(
        node.get(&keys::session_index(&session(1))).is_some(),
        "the index needs the triple"
    );
    assert_eq!(
        node.value::<u64>(&keys::live_sessions()),
        Some(defaults::MAX_SESSIONS - 1)
    );
}

/// Refine lists due rows by their keys alone: a key under the index that
/// is not an expiry key is passed over, and a row whose value was not
/// stored is listed like any.
#[test]
fn refine_lists_due_rows_by_their_keys() {
    let (programs, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let session = Session {
        key: [8; 32],
        name: [8; 16],
        t0: now,
    };
    node.batch(now, [0; 32], vec![increment_in(&programs, session, 1)]);
    let (id, _) = node.session(&session).unwrap();
    let mut malformed = keys::expiry_prefix();
    malformed.extend_from_slice(&[0; 3]);
    node.state.insert(malformed.clone(), stored(&[]));
    node.state
        .insert(keys::expiry(expiry::bucket(now), id), vec![0xff]);
    let due = expiry::due(expiry::bucket(now));
    let result = node.batch(due, [0; 32], vec![Input::Sweep]);
    assert_eq!(swept(&result.steps[0]), vec![(expiry::bucket(now), id)]);
    assert_eq!(node.session(&session), None);
    assert!(node.state.contains_key(&malformed));
}

/// A node with the counter alone installed.
fn counter_only() -> (Programs, Node) {
    let programs = Programs::load();
    let mut node = Node::new();
    let program = node.add(&programs.counter);
    let result = node.batch(
        0,
        [0; 32],
        vec![Input::Admin(Admin::Install {
            instance: COUNTER,
            program,
            attestables: vec![],
            roles: vec![],
        })],
    );
    ran(&result.steps[0]);
    (programs, node)
}

/// The agent's session state, every row of it.
fn session_rows(node: &Node) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let any = Session {
        key: [0; 32],
        name: [0; 16],
        t0: 0,
    };
    let tags: Vec<Vec<u8>> = [
        keys::session(SessionId(0)),
        keys::reply(SessionId(0), 0),
        keys::session_index(&any),
        keys::session_of(SessionId(0)),
        keys::expiry_prefix(),
        keys::key_sessions(&[0; 32]),
        keys::live_sessions(),
        keys::next_session(),
    ]
    .iter()
    .map(|key| key[..2].to_vec())
    .collect();
    node.state
        .iter()
        .filter(|(key, _)| tags.iter().any(|tag| key.starts_with(tag)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// A session as the model holds it.
#[derive(Clone, Debug)]
struct Modelled {
    id: SessionId,
    sequence: u64,
    time: u64,
    /// The replies kept, by sequence.
    replies: BTreeMap<u64, u64>,
}

/// The agent's sessions as the plan defines them, step by step.
#[derive(Clone, Default)]
struct SessionModel {
    sessions: BTreeMap<Session, Modelled>,
    rows: std::collections::BTreeSet<(u64, SessionId)>,
    next: u64,
    created: bool,
    total: u64,
}

impl SessionModel {
    fn live(&self) -> u64 {
        self.sessions.len() as u64
    }

    fn of_key(&self, key: &[u8; 32]) -> u64 {
        self.sessions
            .keys()
            .filter(|session| session.key == *key)
            .count() as u64
    }

    /// What the sweep lists at `time`, and what it does.
    fn sweep(&mut self, time: u64) -> Vec<(u64, SessionId)> {
        let due: Vec<(u64, SessionId)> = self
            .rows
            .iter()
            .take_while(|(bucket, _)| expiry::due(*bucket) <= time)
            .take(defaults::SWEEP_LIMIT)
            .copied()
            .collect();
        for &(bucket, id) in &due {
            self.rows.remove(&(bucket, id));
            let (session, modelled) = self
                .sessions
                .iter()
                .find(|(_, modelled)| modelled.id == id)
                .map(|(session, modelled)| (*session, modelled.clone()))
                .expect("a row's session");
            let creatable = session.t0 + defaults::SESSION_SKEW_MS;
            if time > modelled.time + defaults::SESSION_EXPIRY_MS && time > creatable {
                self.sessions.remove(&session);
            } else {
                self.rows
                    .insert((expiry::bucket(modelled.time.max(creatable)), id));
            }
        }
        due
    }

    /// A request's step in a batch at `time`, as refine decides it: run,
    /// or refused with a code.
    fn refine(&mut self, session: Session, sequence: u64, time: u64) -> Result<(), u32> {
        match self.sessions.get(&session) {
            Some(held) if sequence <= held.sequence => return Err(refusal::SEQUENCE),
            Some(held) if time > held.time + defaults::SESSION_EXPIRY_MS => {
                return Err(refusal::EXPIRED);
            }
            Some(held) if sequence != held.sequence + 1 => return Err(refusal::SEQUENCE),
            Some(_) => {}
            None if session.t0.abs_diff(time) > defaults::SESSION_SKEW_MS => {
                return Err(refusal::STALE_SESSION);
            }
            None if sequence != 1 => return Err(refusal::SEQUENCE),
            None if self.live() >= defaults::MAX_SESSIONS => {
                return Err(refusal::SESSIONS_FULL);
            }
            None if self.of_key(&session.key) >= defaults::MAX_KEY_SESSIONS => {
                return Err(refusal::KEY_SESSIONS_FULL);
            }
            None => {}
        }
        self.apply(session, sequence, time);
        Ok(())
    }

    /// A request that ran, as accumulate applies it: its session created
    /// if the state does not hold it, its mark and reply.
    fn apply(&mut self, session: Session, sequence: u64, time: u64) {
        self.total += 1;
        let total = self.total;
        let modelled = match self.sessions.get_mut(&session) {
            Some(modelled) => modelled,
            None => {
                let id = SessionId(self.next);
                self.next += 1;
                self.created = true;
                self.rows.insert((expiry::bucket(time), id));
                self.sessions.entry(session).or_insert(Modelled {
                    id,
                    sequence: 0,
                    time,
                    replies: BTreeMap::new(),
                })
            }
        };
        modelled.sequence = sequence;
        modelled.time = time;
        modelled.replies.insert(sequence, total);
        if let Some(old) = sequence.checked_sub(defaults::REPLY_WINDOW) {
            modelled.replies.remove(&old);
        }
    }

    /// The rows the agent should hold.
    fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut rows = BTreeMap::new();
        let mut keys_held: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (session, modelled) in &self.sessions {
            let id = modelled.id;
            rows.insert(keys::session_index(session), stored(&id.encode()));
            rows.insert(keys::session_of(id), stored(&session.encode()));
            let mark = SessionMark {
                sequence: modelled.sequence,
                time: modelled.time,
            };
            rows.insert(keys::session(id), stored(&mark.encode()));
            for (sequence, total) in &modelled.replies {
                rows.insert(
                    keys::reply(id, *sequence),
                    stored(&Outcome::Done(total.encode()).encode()),
                );
            }
            *keys_held.entry(session.key).or_default() += 1;
        }
        for (bucket, id) in &self.rows {
            rows.insert(keys::expiry(*bucket, *id), stored(&[]));
        }
        for (key, count) in keys_held {
            rows.insert(keys::key_sessions(&key), stored(&count.encode()));
        }
        if self.created {
            rows.insert(keys::live_sessions(), stored(&self.live().encode()));
            rows.insert(keys::next_session(), stored(&self.next.encode()));
        }
        rows
    }
}

/// A request's choices in a life-cycle batch: key, name, t0, sequence.
type LifeRequest = (u8, u8, u8, u8);

/// One batch of the session life cycle: how far time moves, whether it
/// sweeps, and its requests.
type LifeBatch = (u8, bool, Vec<LifeRequest>);

fn life_batch() -> impl Strategy<Value = LifeBatch> {
    (
        0u8..6,
        any::<bool>(),
        proptest::collection::vec((0u8..2, 0u8..2, 0u8..6, 0u8..5), 0..5),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Sessions live, expire, move and are collected as the model says,
    /// and every session row and count the agent holds is the model's
    /// after every batch.
    #[test]
    fn the_session_life_cycle_matches_the_model(
        batches in proptest::collection::vec(life_batch(), 1..14)
    ) {
        let (programs, mut node) = counter_only();
        let mut model = SessionModel::default();
        let mut time = 100 * defaults::SESSION_BUCKET_MS;
        // The t0 each (key, name) first went with, to send it again.
        let mut first: BTreeMap<(u8, u8), u64> = BTreeMap::new();
        for (advance, sweep, requests) in batches {
            time += match advance {
                0 => 1_000,
                1 => defaults::SESSION_SKEW_MS * 3 / 2,
                2 => defaults::SESSION_BUCKET_MS,
                3 => defaults::SESSION_EXPIRY_MS / 2 + defaults::SESSION_BUCKET_MS,
                _ => defaults::SESSION_EXPIRY_MS + defaults::SESSION_BUCKET_MS,
            };
            let mut inputs = Vec::new();
            if sweep {
                inputs.push(Input::Sweep);
            }
            let mut requested = Vec::new();
            for (key, name, t0, sequence) in requests {
                // Mostly a session sent before, so sessions live on.
                let t0 = match t0 {
                    0 => time,
                    1 => time - defaults::SESSION_SKEW_MS / 2,
                    2 => time - 2 * defaults::SESSION_SKEW_MS,
                    _ => *first.get(&(key, name)).unwrap_or(&time),
                };
                first.entry((key, name)).or_insert(t0);
                let session = Session {
                    key: [10 + key; 32],
                    name: [name; 16],
                    t0,
                };
                let mark = model.sessions.get(&session).map_or(0, |held| held.sequence);
                let sequence = match sequence {
                    0 | 1 => mark + 1,
                    2 => mark.max(1),
                    3 => mark + 2,
                    _ => 1,
                };
                requested.push((session, sequence));
                inputs.push(increment_in(&programs, session, sequence));
            }
            // Refine decides every step on the state before the batch;
            // accumulate sweeps first, then applies the steps that ran.
            let mut refined = model.clone();
            let expected: Vec<Result<(), u32>> = requested
                .iter()
                .map(|(session, sequence)| refined.refine(*session, *sequence, time))
                .collect();
            let listed = sweep.then(|| model.sweep(time));
            for ((session, sequence), expected) in requested.iter().zip(&expected) {
                if expected.is_ok() {
                    model.apply(*session, *sequence, time);
                }
            }
            let result = node.batch(time, [0; 32], inputs);
            let mut steps = result.steps.iter();
            if let Some(listed) = &listed {
                prop_assert_eq!(&swept(steps.next().unwrap()), listed);
            }
            for (step, expected) in steps.zip(&expected) {
                match expected {
                    Ok(()) => {
                        ran(step);
                    }
                    Err(code) => prop_assert_eq!(refused(step), *code),
                }
            }
            prop_assert_eq!(session_rows(&node), model.rows());
        }
    }
}

#[test]
fn kinds_and_unserved_ids_are_enforced() {
    let (programs, mut node, _, mut sessions) = setup();
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, programs.method(COUNTER, "sneaky"), ()),
            sessions.request(ALICE, COUNTER, programs.method(COUNTER, "unserved"), ()),
        ],
    );
    assert_eq!(
        failed(&result.steps[0]),
        failure::TRAPPED,
        "a query may not write"
    );
    assert_eq!(done::<u64>(&result.steps[1]), code::WHAT);
    assert_eq!(
        node.query(
            ALICE,
            COUNTER,
            programs.method(COUNTER, "increment"),
            1u64.encode()
        ),
        Outcome::Failed {
            code: failure::UNKNOWN,
            detail: vec![],
        },
        "a query cannot run a command"
    );
}

#[test]
fn per_step_caps_fail_the_step_and_messages_reach_the_outbox() {
    let (programs, mut node, _, mut sessions) = setup();
    let fill = programs.method(COUNTER, "fill");
    let spam = programs.method(COUNTER, "spam");
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, fill, (5u32, 60_000u32)),
            sessions.request(ALICE, COUNTER, spam, (cap::MESSAGES as u32) + 1),
            sessions.request(ALICE, COUNTER, spam, 2u32),
        ],
    );
    assert_eq!(
        failed(&result.steps[0]),
        failure::CAP,
        "writes past 256 KiB"
    );
    assert_eq!(failed(&result.steps[1]), failure::CAP, "too many messages");
    assert_eq!(ran(&result.steps[2]).messages.len(), 2);
    assert!(node.get(&keys::outbox(AgentId(5), 1)).is_some());
    assert!(node.get(&keys::outbox(AgentId(5), 2)).is_some());
    let next: u64 = decode(&node.get(&keys::pair_out(AgentId(5))).unwrap()).unwrap();
    assert_eq!(next, 2);
}

#[test]
fn each_per_step_cap_holds_its_limit_and_fails_one_byte_past() {
    let (programs, mut node, _, mut sessions) = setup();
    let echo = programs.method(COUNTER, "echo");
    let large = programs.method(COUNTER, "large");
    let fill = programs.method(COUNTER, "fill");
    let put_and_scan = programs.method(COUNTER, "put_and_scan");
    // Past 16 KiB, a byte vector encodes with a 4-byte length.
    let bytes = |encoded: usize| encoded - 4;
    let key = |len: usize| (vec![vec![2u8; len]], vec![2u8], Vec::<u8>::new());
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, echo, vec![1u8; bytes(cap::REQUEST)]),
            sessions.request(ALICE, COUNTER, echo, vec![1u8; bytes(cap::REQUEST) + 1]),
            sessions.request(ALICE, COUNTER, large, bytes(cap::REPLY) as u32),
            sessions.request(ALICE, COUNTER, large, bytes(cap::REPLY) as u32 + 1),
            sessions.request(ALICE, COUNTER, fill, (1u32, bytes(cap::VALUE) as u32)),
            sessions.request(ALICE, COUNTER, fill, (1u32, bytes(cap::VALUE) as u32 + 1)),
            sessions.request(ALICE, COUNTER, put_and_scan, key(cap::KEY)),
            sessions.request(ALICE, COUNTER, put_and_scan, key(cap::KEY + 1)),
        ],
    );
    for (at, past, what) in [
        (0, 1, "a request"),
        (2, 3, "a reply"),
        (4, 5, "a value"),
        (6, 7, "a key"),
    ] {
        assert!(
            matches!(ran(&result.steps[at]).outcome, Outcome::Done(_)),
            "{what} at its cap: {:?}",
            ran(&result.steps[at]).outcome
        );
        assert_eq!(
            failed(&result.steps[past]),
            failure::CAP,
            "{what} past its cap"
        );
    }
}

#[test]
fn an_ack_clears_the_outbox_through_its_sequence() {
    let (programs, mut node, _, mut sessions) = setup();
    let spam = programs.method(COUNTER, "spam");
    node.batch(
        1,
        [0; 32],
        vec![sessions.request(ALICE, COUNTER, spam, 3u32)],
    );
    let to = AgentId(5);
    let pending = |node: &Node| -> Vec<u64> {
        (1..=3)
            .filter(|sequence| node.get(&keys::outbox(to, *sequence)).is_some())
            .collect()
    };
    let acked = |node: &Node| -> u64 { decode(&node.get(&keys::acked(to)).unwrap()).unwrap() };
    assert_eq!(pending(&node), [1, 2, 3]);
    let result = node.batch(
        2,
        [0; 32],
        vec![
            Input::Ack { to, sequence: 2 },
            Input::Ack { to, sequence: 1 },
        ],
    );
    for step in &result.steps {
        assert!(
            matches!(ran(step).outcome, Outcome::Done(_)),
            "an ack is never refused"
        );
    }
    assert_eq!(pending(&node), [3]);
    assert_eq!(acked(&node), 2, "a stale ack changes nothing");
    node.batch(3, [0; 32], vec![Input::Ack { to, sequence: 99 }]);
    assert!(pending(&node).is_empty());
    assert_eq!(acked(&node), 3, "an ack stops at what was sent");
}

#[test]
fn roles_nested_calls_cycles_and_attests() {
    let (programs, mut node, _, mut sessions) = setup();
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(BOB, LEDGER, programs.method(LEDGER, "mint"), (1u64, 10u64)),
            sessions.request(
                ALICE,
                LEDGER,
                programs.method(LEDGER, "mint"),
                (1u64, 100u64),
            ),
            sessions.request(
                ALICE,
                CALLER,
                programs.method(CALLER, "pay"),
                ((LEDGER.0, 1u64), (2u64, 40u64)),
            ),
            sessions.request(ALICE, CALLER, programs.method(CALLER, "recurse"), ()),
            sessions.request(
                ALICE,
                LEDGER,
                programs.method(LEDGER, "audit"),
                vec![1u64, 2],
            ),
            sessions.request(ALICE, CALLER, programs.method(CALLER, "relay"), LEDGER.0),
        ],
    );
    assert_eq!(failed(&result.steps[0]), failure::FORBIDDEN);
    assert_eq!(done::<u64>(&result.steps[1]), 100);
    assert_eq!(done::<u64>(&result.steps[2]), 40);
    let instances: Vec<_> = ran(&result.steps[2])
        .instances
        .iter()
        .map(|entry| entry.instance)
        .collect();
    assert_eq!(instances, [CALLER, LEDGER]);
    assert_eq!(failed(&result.steps[3]), failure::CYCLE);
    assert_eq!(ran(&result.steps[4]).attests.len(), 1);
    assert!(done::<bool>(&result.steps[5]));
    assert!(ran(&result.steps[5]).messages.is_empty());
}

#[test]
fn an_attestable_may_not_write_its_arguments() {
    use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
    // store_ind_u8 [φ7] = φ0, then return to the halt address.
    let scribble = build_standard_program(&StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 0,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code: vec![120, 0x70, 50, 0],
            bitmask: vec![1, 0, 1, 0],
        },
    })
    .unwrap();
    let programs = Programs::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    let ledger = node.add(&programs.ledger);
    let program = node.add(&scribble);
    let checksum = method(&programs.ledger, "checksum");
    node.batch(
        0,
        [0; 32],
        vec![Input::Admin(Admin::Install {
            instance: LEDGER,
            program: ledger,
            attestables: vec![(checksum, program)],
            roles: vec![(b"minter".to_vec(), MINTER)],
        })],
    );
    kit.install(
        LEDGER,
        &programs.ledger,
        &[(checksum, &scribble)],
        &[("minter", MINTER)],
    )
    .unwrap();
    let audit = programs.method(LEDGER, "audit");
    let mut sessions = Sessions::new();
    let result = node.batch(
        1,
        [0; 32],
        vec![sessions.request(ALICE, LEDGER, audit, vec![1u64])],
    );
    assert_eq!(failed(&result.steps[0]), failure::TRAPPED);
    kit.batch(1, [0; 32]);
    let expected = kit.command(ALICE, LEDGER, audit, &vec![1u64].encode());
    assert_eq!(ran(&result.steps[0]).outcome, expected.outcome);
}

#[test]
fn a_call_that_cannot_get_a_machine_fails_the_step() {
    let programs = Programs::load();
    let mut node = Node::new();
    let mut kit = Testkit::new(AGENT);
    let caller = node.add(&programs.caller);
    let installs: Vec<Input> = (100..170)
        .map(|instance| {
            Input::Admin(Admin::Install {
                instance: InstanceId(instance),
                program: caller,
                attestables: vec![],
                roles: vec![],
            })
        })
        .collect();
    node.batch(0, [0; 32], installs);
    for instance in 100..170 {
        kit.install(InstanceId(instance), &programs.caller, &[], &[])
            .unwrap();
    }
    let hop = programs.method(CALLER, "hop");
    let mut sessions = Sessions::new();
    let result = node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, InstanceId(100), hop, (101u32, 10u32)),
            sessions.request(ALICE, InstanceId(100), hop, (101u32, 69u32)),
        ],
    );
    assert_eq!(done::<u32>(&result.steps[0]), 10);
    assert_eq!(failed(&result.steps[1]), failure::DEPTH);
    kit.batch(1, [0; 32]);
    let deep = kit.command(ALICE, InstanceId(100), hop, &(101u32, 10u32).encode());
    assert_eq!(&deep.outcome, &ran(&result.steps[0]).outcome);
    let deeper = kit.command(ALICE, InstanceId(100), hop, &(101u32, 69u32).encode());
    assert_eq!(&deeper.outcome, &ran(&result.steps[1]).outcome);
    assert_eq!(deeper.gas_used, ran(&result.steps[1]).gas_used);
}

#[test]
fn a_refine_dispatches_only_what_its_gas_can_finish() {
    let (programs, node, _, mut sessions) = setup();
    let increment = programs.method(COUNTER, "increment");
    let work = Work::Batch(Batch {
        version: node.version,
        time: 1,
        seed: [0; 32],
        inputs: (0..10)
            .map(|_| sessions.request(ALICE, COUNTER, increment, 1u64))
            .collect(),
    });
    // From less than a handler's limit up: every refine halts with a prefix
    // of the batch, longer as the gas grows.
    let mut counts = Vec::new();
    for gas in (0..60).map(|step| defaults::HANDLER_GAS + step * 100_000) {
        let (result, _) = WorkResult::decode(&node.refine_with(&work, gas)).unwrap();
        for (index, step) in result.steps.iter().enumerate() {
            assert_eq!(done::<u64>(step), index as u64 + 1);
        }
        counts.push(result.steps.len());
    }
    assert_eq!(counts[0], 0);
    assert!(counts.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(counts.iter().any(|count| 0 < *count && *count < 10));
    assert_eq!(*counts.last().unwrap(), 10);
}

#[test]
fn a_refine_stops_before_its_result_outgrows_the_cap() {
    let (programs, mut node, _, mut sessions) = setup();
    let echo = programs.method(COUNTER, "echo");
    let mut inputs: Vec<Input> = (0..80)
        .map(|_| sessions.request(ALICE, COUNTER, echo, vec![7u8; 64_000]))
        .collect();
    let full = node.batch(1, [0; 32], inputs.clone());
    let ran = full.steps.len();
    assert!(0 < ran && ran < inputs.len(), "{ran} steps");
    assert!(full.encode().len() <= cap::WORK_RESULT);
    let rest = node.batch(2, [0; 32], inputs.split_off(ran));
    assert_eq!(rest.steps.len(), 80 - ran, "the rest run next");
    assert_eq!(done::<Vec<u8>>(&rest.steps[0]), vec![7u8; 64_000]);
}

#[test]
fn a_scan_from_any_cursor_sees_the_steps_own_writes() {
    let (programs, mut node, mut kit, mut sessions) = setup();
    let scan = programs.method(COUNTER, "put_and_scan");
    let keys = vec![vec![4u8, 1], vec![4, 2], vec![5, 1]];
    let row = |key: &[u8]| (key.to_vec(), vec![1u8]).encode();
    let both = [row(&[4, 1]), row(&[4, 2])].concat();
    let cases = [
        (vec![], both.clone()),
        (vec![3u8], both.clone()),
        (vec![4], both),
        (vec![4, 1], row(&[4, 2])),
        (vec![4, 9], vec![]),
        (vec![6], vec![]),
    ];
    let arguments = |cursor: &Vec<u8>| (keys.clone(), vec![4u8], cursor.clone());
    let inputs = cases
        .iter()
        .map(|(cursor, _)| sessions.request(ALICE, COUNTER, scan, arguments(cursor)))
        .collect();
    let result = node.batch(1, [0; 32], inputs);
    kit.batch(1, [0; 32]);
    for ((cursor, expected), step) in cases.iter().zip(&result.steps) {
        assert_eq!(&done::<Vec<u8>>(step), expected, "cursor {cursor:?}");
        let reference = kit.command(ALICE, COUNTER, scan, &arguments(cursor).encode());
        assert_eq!(
            reference.outcome,
            ran(step).outcome,
            "testkit, cursor {cursor:?}"
        );
    }
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
    let refine_gas = |node: &Node, inputs: Vec<Input>| {
        let work = Work::Batch(Batch {
            version: node.version,
            time: 1,
            seed: [0; 32],
            inputs,
        });
        let invocation = node.run_refine(&work, OUTER_GAS);
        assert_eq!(invocation.exit, ExitReason::Halt);
        let (result, _) =
            WorkResult::decode(&invocation.output_bounded(cap::WORK_RESULT).unwrap()).unwrap();
        let steps: u64 = result.steps.iter().map(|step| ran(step).gas_used).sum();
        invocation.gas_used - steps
    };
    let empty = refine_gas(&node, vec![]);
    let install = Input::Admin(Admin::Install {
        instance: big_instance,
        program,
        attestables: vec![],
        roles: vec![],
    });
    let installing = refine_gas(&node, vec![install.clone()]) - empty;
    let result = node.batch(1, [0; 32], vec![install]);
    assert!(matches!(ran(&result.steps[0]).outcome, Outcome::Done(_)));
    let request = sessions.request(ALICE, big_instance, MethodId(1), ());
    let reading = refine_gas(&node, vec![request]) - empty;
    println!("install {installing}, first read and run {reading}");
    assert!(
        installing <= defaults::INSTALL_RESERVE * 4 / 5,
        "install: {installing}"
    );
    assert!(
        reading <= defaults::STEP_RESERVE * 4 / 5,
        "first read: {reading}"
    );
}

/// Every program calls only what a JAM node serves, or what has a
/// fallback there (`abi::surface`): the default agent, the test actors and
/// the attestable program, every `ecalli` in them, reachable or not.
#[test]
fn every_program_calls_only_its_surface() {
    use vos_wire::abi::surface;
    let calls = |blob: &[u8]| vos_pvm::spi::inspect_standard_program_host_calls(blob).unwrap();
    let mut seen: Vec<u64> = calls(&agent());
    seen.sort_unstable();
    seen.dedup();
    for call in &seen {
        assert!(surface::agent(*call).is_some(), "the agent calls {call:#x}");
    }
    assert!(
        seen.iter()
            .any(|call| surface::agent(*call) == Some(surface::OnJam::Loader)),
        "the agent instantiates: the check sees its calls"
    );
    let programs = Programs::load();
    for (name, blob) in [
        ("counter", &programs.counter),
        ("ledger", &programs.ledger),
        ("caller", &programs.caller),
    ] {
        for call in calls(blob) {
            assert!(surface::actor(call), "{name} calls {call:#x}");
        }
    }
    for call in calls(&programs.checksum) {
        assert!(surface::attestable(call), "checksum calls {call:#x}");
    }
}

/// Batches that read no state refine on a VOS host (the pool, applied
/// state) and on a JAM host (no pool, no state, no precompiles, programs
/// from preimages) to the same work result, which both accumulate to the
/// same storage. No request or message appears: their session and pair
/// marks are applied state, which this host cannot read.
#[test]
fn vos_and_jam_hosts_agree_on_batches_that_read_no_state() {
    let programs = Programs::load();
    let mut vos = Node::new();
    let mut jam = Node::with(false, false);
    let mut add = |blob: &[u8]| {
        let hash = vos.add(blob);
        assert_eq!(jam.add(blob), hash);
        hash
    };
    let counter = add(&programs.counter);
    let ledger = add(&programs.ledger);
    let checksum = add(&programs.checksum);
    let audit = method(&programs.ledger, "checksum");
    let batches = vec![
        vec![
            Input::Admin(Admin::Install {
                instance: COUNTER,
                program: counter,
                attestables: vec![],
                roles: vec![],
            }),
            Input::Admin(Admin::Install {
                instance: LEDGER,
                program: ledger,
                attestables: vec![(audit, checksum)],
                roles: vec![(b"minter".to_vec(), MINTER)],
            }),
            Input::Admin(Admin::SetRole {
                principal: ALICE,
                role: Some(MINTER),
            }),
        ],
        vec![
            Input::Ack {
                to: AgentId(5),
                sequence: 1,
            },
            Input::Admin(Admin::SetRole {
                principal: ALICE,
                role: None,
            }),
            Input::Admin(Admin::SetRole {
                principal: BOB,
                role: Some(MINTER),
            }),
        ],
    ];
    for (time, inputs) in batches.into_iter().enumerate() {
        let work = Work::Batch(Batch {
            version: vos.version,
            time: time as u64 + 1,
            seed: [time as u8; 32],
            inputs,
        });
        let on_vos = vos.refine(&work);
        let on_jam = jam.refine(&work);
        assert_eq!(on_vos, on_jam, "batch {time}");
        vos.accumulate(&on_vos);
        jam.accumulate(&on_jam);
        vos.version += 1;
        jam.version += 1;
        assert_eq!(vos.state, jam.state, "storage after batch {time}");
    }
}

#[test]
fn without_a_pool_the_loader_builds_the_machines() {
    let programs = Programs::load();
    let mut node = Node::with(false, true);
    let counter = node.add(&programs.counter);
    let increment = programs.method(COUNTER, "increment");
    let mut sessions = Sessions::new();
    let install = Input::Admin(Admin::Install {
        instance: COUNTER,
        program: counter,
        attestables: vec![],
        roles: vec![],
    });
    let first = node.batch(
        1,
        [0; 32],
        vec![install, sessions.request(ALICE, COUNTER, increment, 5u64)],
    );
    assert_eq!(done::<u64>(&first.steps[1]), 5);
    let second = node.batch(
        2,
        [0; 32],
        vec![sessions.request(ALICE, COUNTER, increment, 2u64)],
    );
    assert_eq!(
        done::<u64>(&second.steps[0]),
        7,
        "applied state carries over"
    );
}

#[test]
fn a_refine_that_cannot_read_state_produces_no_result() {
    let programs = Programs::load();
    let mut node = Node::with(false, false);
    let counter = node.add(&programs.counter);
    let increment = programs.method(COUNTER, "increment");
    let mut sessions = Sessions::new();
    // Admin inputs read no state: the install applies.
    node.batch(
        1,
        [0; 32],
        vec![Input::Admin(Admin::Install {
            instance: COUNTER,
            program: counter,
            attestables: vec![],
            roles: vec![],
        })],
    );
    for time in [2, 3] {
        let work = Work::Batch(Batch {
            version: node.version,
            time,
            seed: [0; 32],
            inputs: vec![sessions.request(ALICE, COUNTER, increment, 5u64)],
        });
        assert_eq!(
            node.run_refine(&work, OUTER_GAS).exit,
            ExitReason::Panic,
            "no result computed on empty state"
        );
    }
}

#[test]
fn state_the_agent_did_not_write_fails_only_the_steps_that_read_it() {
    let (programs, mut node, _, mut sessions) = setup();
    let increment = programs.method(COUNTER, "increment");
    let mint = programs.method(LEDGER, "mint");
    let holders = programs.method(LEDGER, "holders");
    node.batch(
        1,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, increment, 5u64),
            sessions.request(ALICE, LEDGER, mint, (1u64, 10u64)),
            sessions.request(ALICE, LEDGER, mint, (2u64, 20u64)),
        ],
    );
    let counter = keys::instance_prefix(COUNTER);
    let rows: Vec<Vec<u8>> = node
        .state
        .keys()
        .filter(|key| key.starts_with(&counter))
        .cloned()
        .collect();
    assert!(!rows.is_empty());
    for key in rows {
        node.state.insert(key, vec![0xff]);
    }
    let balances: Vec<Vec<u8>> = node
        .state
        .keys()
        .filter(|key| key.starts_with(&keys::instance_prefix(LEDGER)))
        .cloned()
        .collect();
    node.state.insert(balances.last().unwrap().clone(), vec![]);
    let bob = Sessions::session(&BOB);
    node.state.insert(keys::session_index(&bob), vec![1, 0xff]);

    let result = node.batch(
        2,
        [0; 32],
        vec![
            sessions.request(ALICE, COUNTER, increment, 1u64),
            sessions.request(ALICE, LEDGER, holders, ()),
            sessions.request(BOB, LEDGER, programs.method(LEDGER, "balance"), 1u64),
            sessions.request(ALICE, LEDGER, programs.method(LEDGER, "balance"), 1u64),
        ],
    );
    assert_eq!(failed(&result.steps[0]), failure::TRAPPED, "a corrupt get");
    assert_eq!(failed(&result.steps[1]), failure::TRAPPED, "a corrupt scan");
    assert!(
        matches!(
            result.steps[2],
            Step::Refused {
                code: refusal::UNREADABLE,
                ..
            }
        ),
        "a corrupt session index refuses: {:?}",
        result.steps[2]
    );
    assert_eq!(done::<u64>(&result.steps[3]), 10, "other rows still read");
}

/// One random request among the test actors' handlers.
fn input() -> impl Strategy<Value = (u8, u8, u64, u64)> {
    (0u8..16, 0u8..2, 0u64..200, 0u64..4)
}

fn request(programs: &Programs, sessions: &mut Sessions, choice: (u8, u8, u64, u64)) -> Input {
    let (handler, who, amount, account) = choice;
    let caller = if who == 0 { ALICE } else { BOB };
    let m = |instance, name| programs.method(instance, name);
    match handler {
        0 => sessions.request(caller, COUNTER, m(COUNTER, "increment"), amount),
        1 => sessions.request(caller, COUNTER, m(COUNTER, "value"), ()),
        2 => sessions.request(caller, COUNTER, m(COUNTER, "stamp"), ()),
        3 => sessions.request(
            caller,
            COUNTER,
            m(COUNTER, "fill"),
            (amount as u32 % 4, 100u32),
        ),
        4 => sessions.request(caller, COUNTER, m(COUNTER, "spam"), amount as u32 % 3),
        5 => sessions.request(caller, LEDGER, m(LEDGER, "mint"), (account, amount)),
        6 => sessions.request(
            caller,
            LEDGER,
            m(LEDGER, "transfer"),
            ((account, (account + 1) % 4), amount),
        ),
        7 => sessions.request(caller, LEDGER, m(LEDGER, "balance"), account),
        8 => sessions.request(caller, LEDGER, m(LEDGER, "holders"), ()),
        9 => sessions.request(caller, LEDGER, m(LEDGER, "audit"), vec![amount, account]),
        10 => sessions.request(
            caller,
            CALLER,
            m(CALLER, "pay"),
            ((LEDGER.0, account), ((account + 2) % 4, amount)),
        ),
        11 => sessions.request(caller, CALLER, m(CALLER, "relay"), LEDGER.0),
        12 => sessions.request(caller, CALLER, m(CALLER, "ask"), LEDGER.0),
        13 => sessions.request(caller, CALLER, m(CALLER, "recurse"), ()),
        14 => sessions.request(caller, LEDGER, m(LEDGER, "whoami"), ()),
        _ => sessions.request(caller, LEDGER, m(LEDGER, "total"), ()),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Random batches through the agent agree with the testkit step by
    /// step: outcomes, writes, messages, attests, per-instance gas and
    /// state.
    #[test]
    fn the_agent_matches_the_reference_model(
        batches in prop::collection::vec(prop::collection::vec(input(), 1..6), 1..4),
        seed in any::<[u8; 32]>(),
    ) {
        let (programs, mut node, mut kit, mut sessions) = setup();
        for (number, choices) in batches.into_iter().enumerate() {
            let time = 1 + number as u64;
            let inputs: Vec<Input> = choices
                .into_iter()
                .map(|choice| request(&programs, &mut sessions, choice))
                .collect();
            let result = node.batch(time, seed, inputs.clone());
            kit.batch(time, seed);
            prop_assert_eq!(result.steps.len(), inputs.len());
            for (step, input) in result.steps.iter().zip(&inputs) {
                let Input::Request(request) = input else { unreachable!() };
                let expected = kit.command(request.caller, request.instance, request.method, &request.arguments);
                let run = ran(step);
                prop_assert_eq!(&run.outcome, &expected.outcome);
                prop_assert_eq!(&run.writes, &expected.writes);
                prop_assert_eq!(&run.messages, &expected.messages);
                prop_assert_eq!(&run.attests, &expected.attests);
                prop_assert_eq!(&run.instances, &expected.instances);
                prop_assert_eq!(run.gas_used, expected.gas_used);
            }
        }
        let applied: BTreeMap<Vec<u8>, Vec<u8>> = node
            .state
            .iter()
            .filter(|(key, _)| key.first() == Some(&0x01))
            .map(|(key, value)| (key.clone(), unstored(value).unwrap().to_vec()))
            .collect();
        let reference: BTreeMap<Vec<u8>, Vec<u8>> = kit.rows().into_iter().collect();
        prop_assert_eq!(applied, reference);
    }
}

/// A refine's gas is the agent's serving plus its steps' gas, which holds
/// what the actors run and what they are charged. Over a phase of one kind
/// of operation, the slope of their difference is what the agent spends per
/// operation beyond its charge. Measured at a handler's limit, after the
/// writes that make the agent's overlays largest (a step's own, and a
/// batch's worth before it), it must leave a fifth of the charge spare.
#[test]
fn every_operation_pays_for_its_serving() {
    use vos_wire::abi::price::{
        self, GET, LOG, MACHINE, OPERATION, PER_BYTE, PUT, RANDOM, SCAN, SEND,
    };
    let (programs, node, _, _) = setup();
    let ops = programs.method(COUNTER, "ops");
    let total = programs.method(LEDGER, "total");
    let audits = programs.method(LEDGER, "audits");
    // Steps in one batch, each a request; the agent's gas beyond theirs.
    let unpaid = |steps: Vec<(InstanceId, MethodId, Vec<u8>)>| -> i64 {
        let inputs = steps
            .into_iter()
            .enumerate()
            .map(|(index, (instance, method, arguments))| {
                Input::Request(Request {
                    session: Sessions::session(&ALICE),
                    sequence: index as u64 + 1,
                    caller: ALICE,
                    instance,
                    method,
                    arguments,
                })
            })
            .collect();
        let work = Work::Batch(Batch {
            version: node.version,
            time: 1,
            seed: [0; 32],
            inputs,
        });
        let invocation = node.run_refine(&work, OUTER_GAS);
        assert_eq!(invocation.exit, ExitReason::Halt);
        let (result, _) =
            WorkResult::decode(&invocation.output_bounded(cap::WORK_RESULT).unwrap()).unwrap();
        let mut steps = 0;
        for step in &result.steps {
            let step = ran(step);
            assert!(
                matches!(step.outcome, Outcome::Done(_)),
                "{:?}",
                step.outcome
            );
            steps += step.gas_used as i64;
        }
        invocation.gas_used as i64 - steps
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
        (
            "get of an absent key",
            false,
            vec![],
            2,
            1000,
            GET + bytes(4),
        ),
        (
            "get after 1,000 writes",
            false,
            vec![(3, 0, 1000)],
            2,
            1000,
            GET + bytes(5),
        ),
        (
            "get after a batch of writes",
            true,
            vec![],
            2,
            1000,
            GET + bytes(4),
        ),
        (
            "put after 500 writes",
            false,
            vec![(3, 0, 500)],
            3,
            900,
            PUT + bytes(5),
        ),
        (
            "put after a batch of writes",
            true,
            vec![],
            3,
            1400,
            PUT + bytes(5),
        ),
        (
            "delete after 500 writes",
            false,
            vec![(3, 0, 500)],
            11,
            500,
            PUT + bytes(4),
        ),
        ("put of 4 KiB", false, vec![], 7, 60, PUT + bytes(4 + 4096)),
        (
            "get of a 1 KiB key after 240 such writes",
            false,
            vec![(15, 0, 240)],
            14,
            240,
            GET + bytes(1025),
        ),
        (
            "put of a 1 KiB key",
            false,
            vec![(15, 0, 120)],
            15,
            120,
            PUT + bytes(1025),
        ),
        (
            "scan after 1,000 writes",
            false,
            vec![(3, 0, 1000)],
            4,
            300,
            SCAN + bytes(1),
        ),
        (
            "scan after a batch of writes",
            true,
            vec![],
            4,
            300,
            SCAN + bytes(1),
        ),
        ("call", false, vec![], 6, 1000, MACHINE),
    ];
    let mut short = Vec::new();
    for (name, batched, before, kind, count, charge) in cases {
        let mut with = before.clone();
        let start = if matches!(kind, 3 | 15) {
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
    programs.install(&mut deep, &mut kit);
    let caller = deep.add(&programs.caller);
    let installs = (100..170)
        .map(|instance| {
            Input::Admin(Admin::Install {
                instance: InstanceId(instance),
                program: caller,
                attestables: vec![],
                roles: vec![],
            })
        })
        .collect();
    deep.batch(1, [0; 32], installs);
    let dive = programs.method(CALLER, "dive");
    let at_depth = |kind: u8, count: u32| -> i64 {
        let work = Work::Batch(Batch {
            version: deep.version,
            time: 1,
            seed: [0; 32],
            inputs: vec![Input::Request(Request {
                session: Sessions::session(&ALICE),
                sequence: 1,
                caller: ALICE,
                instance: InstanceId(100),
                method: dive,
                arguments: ((101u32, 60u32), (kind, count)).encode(),
            })],
        });
        let invocation = deep.run_refine(&work, OUTER_GAS);
        let (result, _) =
            WorkResult::decode(&invocation.output_bounded(cap::WORK_RESULT).unwrap()).unwrap();
        let step = ran(&result.steps[0]);
        assert!(
            matches!(step.outcome, Outcome::Done(_)),
            "{:?}",
            step.outcome
        );
        invocation.gas_used as i64 - step.gas_used as i64
    };
    for (name, kind, count, charge) in [
        ("get through 61 frames", 0, 1000, GET + bytes(4)),
        ("scan through 61 frames", 1, 300, SCAN + bytes(1)),
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
