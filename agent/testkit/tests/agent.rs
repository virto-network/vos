//! The default agent (`agent/default`, built by `just build-agent`) on the
//! node's refine and accumulate hosts, step by step against the testkit.
//! The tests fail, not skip, when the programs are missing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use proptest::prelude::*;
use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{AccumulateContext, ServiceStorage};
use vos_pvm::pool::MachinePool;
use vos_pvm::refine::{Machine, PreparedProgram};
use vos_pvm::refine_host::{RefineContext, StateReader};
use vos_testkit::{Testkit, decode, program_hash};
use vos_wire::abi::{cap, code, failure, refusal};
use vos_wire::batch::{Admin, Batch, Input, Query, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, SessionId};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::{Outcome, Run, Step, WorkResult};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, keys};

const AGENT: AgentId = AgentId(7);
const COUNTER: InstanceId = InstanceId(1);
const LEDGER: InstanceId = InstanceId(2);
const CALLER: InstanceId = InstanceId(3);
const ALICE: Principal = Principal::Client([1; 32]);
const BOB: Principal = Principal::Client([2; 32]);
const MINTER: u8 = 1;
const OUTER_GAS: u64 = 4_000_000_000;

fn elf(path: &str) -> Vec<u8> {
    let path = format!("{}/../{path}", env!("CARGO_MANIFEST_DIR"));
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("{path}: {error}; run `just build-agent build-test-actors`")
    });
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

fn actor(name: &str) -> Vec<u8> {
    elf(&format!(
        "test-actors/target/riscv64em-vos/release/{name}.elf"
    ))
}

fn method(program: &[u8], name: &str) -> MethodId {
    let parsed = vos_pvm::spi::parse_standard_program(program).unwrap();
    Schema::read(&parsed.ro_data)
        .unwrap()
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

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
    agent: Vec<u8>,
    accumulate: PreparedProgram,
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
        let agent = elf("default/target/riscv64em-vos/release/vos-agent.elf");
        Self {
            accumulate: PreparedProgram::new(&agent).unwrap(),
            agent,
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
        let mut context = RefineContext::load(&self.agent, &arguments, gas).unwrap();
        if let Some(pool) = &self.pool {
            context = context.with_pool(Arc::clone(pool));
        }
        if self.serves_state {
            context = context.with_state(Arc::new(Snapshot(self.state.clone())));
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
            &self.accumulate,
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

    fn session(caller: &Principal) -> SessionId {
        match caller {
            Principal::Client(key) => SessionId(u64::from(key[0])),
            _ => SessionId(0),
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
        Step::Refused { .. } => panic!("refused: {step:?}"),
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
    let mark: SessionMark = decode(&node.get(&keys::session(SessionId(1))).unwrap()).unwrap();
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
    let request = |sequence: u64| {
        Input::Request(Request {
            session: SessionId(9),
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
    assert_eq!(
        node.get(&keys::reply(SessionId(9), 2)),
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
    node.state.insert(keys::session(bob), vec![1, 0xff]);

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
        "a corrupt session mark refuses: {:?}",
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
                    session: SessionId(1),
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
        ("send", false, vec![], 5, 16, SEND),
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
                session: SessionId(1),
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
    let attest = |count: u32| vec![(LEDGER, audits, count.encode())];
    let cost = MACHINE as i64 + (unpaid(attest(16)) - unpaid(attest(0))) / 16;
    println!("attest: charged {MACHINE}, costs the agent {cost}");
    if cost > MACHINE as i64 * 4 / 5 {
        short.push("attest");
    }
    assert!(short.is_empty(), "priced without a fifth spare: {short:?}");
}
