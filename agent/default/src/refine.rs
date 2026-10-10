//! Refine: a batch's inputs as steps, each an actor invocation served
//! against overlays of this refine's writes, or a query on applied state.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use vos_wire::abi::{self, Kind, cap, code, failure, op, price, refusal};
use vos_wire::batch::{Admin, Batch, Input, Query, Work};
use vos_wire::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
};
use vos_wire::jam::RefineArgs;
use vos_wire::records::{Installed, SessionMark, unstored};
use vos_wire::result::{
    Attest, InputRef, InstanceGas, Outcome, Outgoing, ResultWriter, Run, Step, Write,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, keys};

use crate::host::{STATE_SCAN, ecalli, gas, ptr, state_read, state_read_into, unserved};
use crate::machines::{ARGUMENTS, Exit, Machine, Unavailable};

/// Nested invocations a step may hold at once.
const MAX_DEPTH: usize = 63;
/// Applied rows fetched per `state_scan` at first; a page grows to
/// [`cap::SCAN`], room for the largest row, when a row needs it.
const SCAN_PAGE: usize = 4096;
/// Where a program's schema starts: the read-only zone.
const SCHEMA_AT: u64 = 1 << 16;

type Overlay = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

pub fn run(arguments: &[u8]) -> Vec<u8> {
    let arguments = RefineArgs::decode(arguments).expect("refine arguments");
    let (work, _) = Work::decode(&arguments.payload).expect("a work item");
    let agent = AgentId(arguments.service as u32);
    match work {
        Work::Batch(batch) => run_batch(agent, batch),
        Work::Query(query) => run_query(agent, query).encode(),
    }
}

/// A stored value without its format byte, or an agent record that does
/// not decode: state the agent did not write. It fails the step that reads
/// it, so one bad row cannot stop the agent.
#[derive(Clone, Copy, Debug)]
struct Corrupt;

impl From<Corrupt> for u32 {
    fn from(_: Corrupt) -> u32 {
        failure::TRAPPED
    }
}

/// A value of applied state, by agent-relative key.
fn applied(key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
    state_read(key)
        .map(|bytes| unstored(&bytes).map(<[u8]>::to_vec).ok_or(Corrupt))
        .transpose()
}

/// An agent record of applied state. A small one, as marks and ids are,
/// is read and decoded on the stack.
fn record<T: Decode>(key: &[u8]) -> Result<Option<T>, Corrupt> {
    let decode = |bytes: &[u8]| {
        let value = unstored(bytes).ok_or(Corrupt)?;
        T::decode(value)
            .map(|(value, _)| Some(value))
            .map_err(|_| Corrupt)
    };
    let mut small = [0u8; 32];
    match state_read_into(key, &mut small) {
        None => Ok(None),
        Some(len) if len <= small.len() => decode(&small[..len]),
        Some(_) => state_read(key).map_or(Ok(None), |bytes| decode(&bytes)),
    }
}

/// Applied rows under `prefix` after `after`, a page at a time.
fn applied_rows(prefix: &[u8], after: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Corrupt> {
    let mut capacity = SCAN_PAGE;
    let out = loop {
        let mut out: Vec<u8> = Vec::with_capacity(capacity);
        let (written, _) = ecalli!(
            STATE_SCAN,
            [
                ptr(prefix),
                prefix.len() as u64,
                ptr(after),
                after.len() as u64,
                out.as_mut_ptr() as u64,
                capacity as u64
            ]
        );
        match written {
            code::WHAT => unserved(),
            code::FULL => {
                assert!(capacity < cap::SCAN, "a stored row larger than a scan");
                capacity = cap::SCAN;
            }
            written => {
                // SAFETY: the host wrote `written` bytes, at most the
                // capacity, from the start.
                unsafe { out.set_len(written as usize) };
                break out;
            }
        }
    };
    let mut rows = Vec::new();
    let mut at = 0;
    while at < out.len() {
        // A row the node framed wrongly is the node's bug, not state the
        // agent did not write: it traps the refine.
        let ((key, value), used) = <(Vec<u8>, Vec<u8>)>::decode(&out[at..]).expect("a row");
        at += used;
        rows.push((key, unstored(&value).ok_or(Corrupt)?.to_vec()));
    }
    Ok(rows)
}

/// What one refine has committed so far, above applied state.
struct Base {
    agent: AgentId,
    time: u64,
    seed: [u8; 32],
    /// Writes of the steps already committed in this refine, in order.
    committed: Overlay,
    /// Installed records read in this refine. Only admin steps change
    /// them, and they clear it.
    installed: RefCell<BTreeMap<InstanceId, Option<Rc<Installed>>>>,
}

impl Base {
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        match self.committed.get(key) {
            Some(value) => Ok(value.clone()),
            None => applied(key),
        }
    }

    fn installed(&self, instance: InstanceId) -> Result<Option<Rc<Installed>>, Corrupt> {
        if let Some(cached) = self.installed.borrow().get(&instance) {
            return Ok(cached.clone());
        }
        let installed = match self.read(&keys::installed(instance))? {
            Some(bytes) => Some(Rc::new(Installed::decode(&bytes).map_err(|_| Corrupt)?.0)),
            None => None,
        };
        self.installed
            .borrow_mut()
            .insert(instance, installed.clone());
        Ok(installed)
    }
}

/// A mark a step advances once it is in the result.
enum Mark {
    Session(Session, Held),
    Pair(AgentId, u64),
}

/// A request's session as this refine sees it: its id, none for a session
/// the state does not hold, and its mark, none for one no step has
/// created.
type Held = (Option<SessionId>, Option<SessionMark>);

/// A session as the in-batch map orders it: by its name as a number
/// first, then its time, then its key, so sessions compare in a few
/// instructions and one key's many sessions differ at once.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ByName(Session);

impl PartialOrd for ByName {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ByName {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        u128::from_le_bytes(self.0.name)
            .cmp(&u128::from_le_bytes(other.0.name))
            .then(self.0.t0.cmp(&other.0.t0))
            .then_with(|| self.0.key.cmp(&other.0.key))
    }
}

/// A session as applied state holds it.
fn held(session: &Session) -> Result<Held, Corrupt> {
    match record::<SessionId>(&keys::session_index_key(session))? {
        Some(id) => {
            let mark = record::<SessionMark>(&keys::session(id))?.ok_or(Corrupt)?;
            Ok((Some(id), Some(mark)))
        }
        None => Ok((None, None)),
    }
}

fn run_batch(agent: AgentId, batch: Batch) -> Vec<u8> {
    let mut base = Base {
        agent,
        time: batch.time,
        seed: batch.seed,
        committed: BTreeMap::new(),
        installed: RefCell::new(BTreeMap::new()),
    };
    let mut sessions: BTreeMap<ByName, Held> = BTreeMap::new();
    let mut pairs: BTreeMap<AgentId, u64> = BTreeMap::new();
    let mut result = ResultWriter::new(batch.version, batch.time, batch.seed);
    for (index, input) in batch.inputs.into_iter().enumerate() {
        let index = index as u32;
        // Dispatch only what the refine's gas can finish. The reserve comes
        // first: reading an input's installed record can cost most of it.
        let reserve = match input {
            Input::Admin(_) => defaults::INSTALL_RESERVE,
            _ => defaults::STEP_RESERVE,
        } + defaults::FINISH_RESERVE;
        if gas() < reserve {
            break;
        }
        let limit = match &input {
            Input::Request(request) => limit(&base, request.instance, request.method),
            Input::Message(message) => limit(&base, message.instance, message.method),
            Input::Admin(_) | Input::Ack { .. } => 0,
        };
        if gas() < limit + reserve {
            break;
        }
        let admin = matches!(input, Input::Admin(_));
        let (step, mark) = match input {
            Input::Request(request) => {
                let held = match sessions.get(&ByName(request.session)) {
                    Some(held) => Ok(*held),
                    None => held(&request.session),
                };
                // A session the state does not hold names itself whole.
                let session = match held {
                    Ok((Some(id), _)) => SessionRef::Known(id),
                    _ => SessionRef::New(alloc::boxed::Box::new(request.session)),
                };
                let input = InputRef::Request {
                    session,
                    sequence: request.sequence,
                };
                let refusal = match held {
                    Err(Corrupt) => Some(refusal::UNREADABLE),
                    Ok((_, Some(mark)))
                        if base.time > mark.time.saturating_add(defaults::SESSION_EXPIRY_MS) =>
                    {
                        Some(refusal::EXPIRED)
                    }
                    Ok((_, None))
                        if request.session.t0.abs_diff(base.time) > defaults::SESSION_SKEW_MS =>
                    {
                        Some(refusal::STALE_SESSION)
                    }
                    Ok((_, mark))
                        if request.sequence != mark.map_or(1, |mark| mark.sequence + 1) =>
                    {
                        Some(refusal::SEQUENCE)
                    }
                    Ok(_) => None,
                };
                if let Some(code) = refusal {
                    (Step::Refused { input, code }, None)
                } else {
                    let mark = SessionMark {
                        sequence: request.sequence,
                        time: base.time,
                    };
                    let step = command(
                        &base,
                        index,
                        input,
                        request.caller,
                        request.instance,
                        request.method,
                        &request.arguments,
                    );
                    let id = held.ok().and_then(|(id, _)| id);
                    (step, Some(Mark::Session(request.session, (id, Some(mark)))))
                }
            }
            Input::Message(message) => {
                let input = InputRef::Message {
                    from: message.from,
                    sequence: message.sequence,
                };
                let mark = match pairs.get(&message.from) {
                    Some(mark) => Ok(Some(*mark)),
                    None => record::<u64>(&keys::pair_in(message.from)),
                };
                let refusal = match mark {
                    Err(Corrupt) => Some(refusal::UNREADABLE),
                    Ok(mark) if message.sequence != mark.unwrap_or(0) + 1 => {
                        Some(refusal::SEQUENCE)
                    }
                    Ok(_) => None,
                };
                if let Some(code) = refusal {
                    (Step::Refused { input, code }, None)
                } else {
                    let step = command(
                        &base,
                        index,
                        input,
                        Principal::Agent(message.from),
                        message.instance,
                        message.method,
                        &message.arguments,
                    );
                    (step, Some(Mark::Pair(message.from, message.sequence)))
                }
            }
            Input::Admin(admin) => (self::admin(admin), None),
            Input::Ack { to, sequence } => (acknowledge(to, sequence), None),
        };
        // A step the result cannot hold waits, with every later input, for
        // the next batch; one alone always fits (`cap::STEP_RESULT`).
        if !result.push(&step) {
            break;
        }
        if let Step::Ran(run) = &step {
            for write in &run.writes {
                base.committed
                    .insert(write.key.clone(), write.value.clone());
            }
        }
        if admin {
            // An admin step may change installed records.
            base.installed.borrow_mut().clear();
        }
        match mark {
            Some(Mark::Session(session, held)) => {
                sessions.insert(ByName(session), held);
            }
            Some(Mark::Pair(from, sequence)) => {
                pairs.insert(from, sequence);
            }
            None => {}
        }
    }
    result.finish()
}

/// The gas limit a handler's schema requests, capped; 0 for an input that
/// will fail before running.
fn limit(base: &Base, instance: InstanceId, method: MethodId) -> u64 {
    base.installed(instance)
        .ok()
        .flatten()
        .and_then(|installed| installed.schema.method(method).map(|schema| schema.gas))
        .map_or(0, |gas| {
            gas.unwrap_or(defaults::HANDLER_GAS)
                .min(defaults::MAX_HANDLER_GAS)
        })
}

#[allow(clippy::too_many_arguments)]
fn command(
    base: &Base,
    index: u32,
    input: InputRef,
    caller: Principal,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Step {
    let mut invocation = Invocation::new(base, index, Kind::Command);
    let outcome = invocation.top(caller, instance, method, arguments);
    let Invocation {
        mut frames,
        instances,
        messages,
        attests,
        gas_used,
        ..
    } = invocation;
    let run = match outcome {
        Outcome::Done(reply) => {
            let overlay = frames.pop().expect("the step overlay");
            let writes: Vec<Write> = overlay
                .into_iter()
                .map(|(key, value)| Write { key, value })
                .collect();
            Run {
                input,
                outcome: Outcome::Done(reply),
                instances,
                writes,
                messages,
                attests,
                gas_used,
            }
        }
        failed => Run {
            input,
            outcome: failed,
            instances,
            writes: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            gas_used,
        },
    };
    Step::Ran(run)
}

fn run_query(agent: AgentId, query: Query) -> Outcome {
    let base = Base {
        agent,
        time: query.time,
        seed: query.seed,
        committed: BTreeMap::new(),
        installed: RefCell::new(BTreeMap::new()),
    };
    let mut invocation = Invocation::new(&base, 0, Kind::Query);
    invocation.top(query.caller, query.instance, query.method, &query.arguments)
}

/// An acknowledgement from agent `to`: unsequenced, never refused, and
/// it runs no actor. Accumulate clears the outbox through `sequence`.
fn acknowledge(to: AgentId, sequence: u64) -> Step {
    Step::Ran(Run {
        input: InputRef::Ack { to, sequence },
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        gas_used: 0,
    })
}

/// An operator command: install a package or set a role. Its writes are
/// under the step write cap like any step's.
fn admin(admin: Admin) -> Step {
    let failed = |code| {
        Step::Ran(Run {
            input: InputRef::Admin,
            outcome: Outcome::Failed {
                code,
                detail: Vec::new(),
            },
            instances: Vec::new(),
            writes: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            gas_used: 0,
        })
    };
    let write = match admin {
        Admin::Install {
            instance,
            program,
            attestables,
            roles,
        } => {
            let Some(installed) = install(program, attestables, roles) else {
                return failed(failure::UNKNOWN);
            };
            Write {
                key: keys::installed(instance),
                value: Some(installed.encode()),
            }
        }
        Admin::SetRole { principal, role } => Write {
            key: keys::member(&principal),
            value: role.map(|role| alloc::vec![role]),
        },
    };
    if write.key.len() + write.value.as_ref().map_or(0, Vec::len) > cap::STEP_WRITES {
        return failed(failure::CAP);
    }
    Step::Ran(Run {
        input: InputRef::Admin,
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes: alloc::vec![write],
        messages: Vec::new(),
        attests: Vec::new(),
        gas_used: 0,
    })
}

/// Read a program's schema from its machine and check the package binds
/// every attestable method and maps every role name.
fn install(
    program: ProgramHash,
    attestables: Vec<(MethodId, ProgramHash)>,
    roles: Vec<(Vec<u8>, u8)>,
) -> Option<Installed> {
    let machine = Machine::acquire(&program.0).ok()?;
    let header = machine.peek(SCHEMA_AT, 8)?;
    let len = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if len > vos_wire::schema::MAX_LEN {
        return None;
    }
    let section = machine.peek(SCHEMA_AT, 8 + len)?;
    let schema = Schema::read(&section).ok()?;
    let installed = Installed {
        program,
        attestables,
        roles,
        schema,
    };
    for method in &installed.schema.methods {
        if method.kind == Kind::Attestable && installed.attestable(method.id).is_none() {
            return None;
        }
        if let Some(role) = &method.role
            && installed.role(role).is_none()
        {
            return None;
        }
    }
    Some(installed)
}

enum Ended {
    Replied(Vec<u8>),
    Failed(Vec<u8>),
    Forbidden,
}

/// One step: its overlays, call stack and effects.
struct Invocation<'a> {
    base: &'a Base,
    step: u32,
    entry: Kind,
    /// The step overlay, then one per nested call.
    frames: Vec<Overlay>,
    stack: Vec<InstanceId>,
    /// Gas the callees of each invocation on the stack used.
    nested: Vec<u64>,
    instances: Vec<InstanceGas>,
    messages: Vec<Outgoing>,
    attests: Vec<Attest>,
    written: usize,
    draws: u64,
    gas_used: u64,
}

impl<'a> Invocation<'a> {
    fn new(base: &'a Base, step: u32, entry: Kind) -> Self {
        Self {
            base,
            step,
            entry,
            frames: alloc::vec![BTreeMap::new()],
            stack: Vec::new(),
            nested: Vec::new(),
            instances: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            written: 0,
            draws: 0,
            gas_used: 0,
        }
    }

    fn top(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Outcome {
        let failed = |code| Outcome::Failed {
            code,
            detail: Vec::new(),
        };
        if arguments.len() > cap::REQUEST {
            return failed(failure::CAP);
        }
        let installed = match self.installed(instance) {
            Ok(installed) => installed,
            Err(code) => return failed(code),
        };
        let Some(schema) = installed.schema.method(method) else {
            return failed(failure::UNKNOWN);
        };
        if schema.kind == Kind::Attestable
            || (self.entry == Kind::Query && schema.kind != Kind::Query)
        {
            return failed(failure::UNKNOWN);
        }
        let gas = schema
            .gas
            .unwrap_or(defaults::HANDLER_GAS)
            .min(defaults::MAX_HANDLER_GAS);
        match self.invoke(caller, instance, method, arguments, gas) {
            Ok((ended, used)) => {
                self.gas_used = used;
                match ended {
                    Ended::Replied(reply) => Outcome::Done(reply),
                    Ended::Failed(detail) => Outcome::Failed {
                        code: failure::HANDLER,
                        detail,
                    },
                    Ended::Forbidden => failed(failure::FORBIDDEN),
                }
            }
            Err((code, used)) => {
                self.gas_used = used;
                failed(code)
            }
        }
    }

    /// Run one invocation with `gas`: how it ended and the gas it used,
    /// or a failure of the whole step with the gas used.
    fn invoke(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        gas: u64,
    ) -> Result<(Ended, u64), (u32, u64)> {
        let installed = self.installed(instance).map_err(|code| (code, 0))?;
        let schema = installed
            .schema
            .method(method)
            .ok_or((failure::UNKNOWN, 0))?;
        if let Some(role) = &schema.role {
            let required = installed.role(role).expect("checked at install");
            if self.role(&caller).map_err(|_| (failure::TRAPPED, 0))? != Some(required) {
                return Ok((Ended::Forbidden, 0));
            }
        }
        if self.stack.contains(&instance) {
            return Err((failure::CYCLE, 0));
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err((failure::DEPTH, 0));
        }
        let kind = schema.kind;
        let mut machine =
            Machine::acquire(&installed.program.0).map_err(|unavailable| match unavailable {
                Unavailable::Full => (failure::DEPTH, 0),
                Unavailable::Missing => (failure::UNKNOWN, 0),
            })?;
        machine.set_gas(gas);
        machine.set_register(7, u64::from(method.0));
        machine.set_register(8, u64::from(kind.encode()[0]));
        machine.set_register(9, arguments.len() as u64);
        if !self
            .instances
            .iter()
            .any(|entry| entry.instance == instance)
        {
            self.instances.push(InstanceGas { instance, gas: 0 });
        }
        self.stack.push(instance);
        self.nested.push(0);
        let ended = self.serve(&mut machine, &installed, caller, instance, kind, arguments);
        self.stack.pop();
        let nested = self.nested.pop().expect("this invocation's entry");
        let used = gas - machine.gas();
        let entry = self
            .instances
            .iter_mut()
            .find(|entry| entry.instance == instance)
            .expect("recorded when it started");
        entry.gas += used - nested;
        match ended {
            Ok(ended) => Ok((ended, used)),
            Err(code) => Err((code, used)),
        }
    }

    /// An instance's installed record: actors cannot write system keys,
    /// so the refine's committed writes and applied state hold it.
    fn installed(&self, instance: InstanceId) -> Result<Rc<Installed>, u32> {
        self.base.installed(instance)?.ok_or(failure::UNKNOWN)
    }

    fn role(&self, principal: &Principal) -> Result<Option<u8>, Corrupt> {
        Ok(self
            .read_state(&keys::member(principal))?
            .and_then(|bytes| bytes.first().copied()))
    }

    fn serve(
        &mut self,
        machine: &mut Machine,
        installed: &Installed,
        caller: Principal,
        instance: InstanceId,
        kind: Kind,
        arguments: &[u8],
    ) -> Result<Ended, u32> {
        let mut outcome: Option<Ended> = None;
        loop {
            match machine.invoke() {
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::OutOfGas => return Err(failure::OUT_OF_GAS),
                Exit::Panic | Exit::Fault => return Err(failure::TRAPPED),
                Exit::Host(id) => {
                    if !known(id) {
                        if !machine.charge(price::OPERATION) {
                            return Err(failure::OUT_OF_GAS);
                        }
                        machine.set_register(7, code::WHAT);
                        continue;
                    }
                    if !abi::allowed(kind, id) {
                        return Err(failure::TRAPPED);
                    }
                    if !machine.charge(price::of(id)) {
                        return Err(failure::OUT_OF_GAS);
                    }
                    self.operation(
                        machine,
                        installed,
                        id,
                        caller,
                        instance,
                        kind,
                        arguments,
                        &mut outcome,
                    )?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn operation(
        &mut self,
        machine: &mut Machine,
        installed: &Installed,
        id: u64,
        caller: Principal,
        instance: InstanceId,
        kind: Kind,
        arguments: &[u8],
        outcome: &mut Option<Ended>,
    ) -> Result<(), u32> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        match id {
            op::INPUT => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.set_register(7, arguments.len() as u64);
            }
            op::REPLY | op::FAIL => {
                if outcome.is_some() {
                    return Err(failure::TRAPPED);
                }
                let bytes = read(machine, r[7], r[8], cap::REPLY)?;
                *outcome = Some(if id == op::REPLY {
                    Ended::Replied(bytes)
                } else {
                    Ended::Failed(bytes)
                });
                machine.set_register(7, code::OK);
            }
            op::LOG => {
                read(machine, r[8], r[9], 4096)?;
                machine.set_register(7, code::OK);
            }
            op::CALLER => {
                let encoded = caller.encode();
                copy_out(machine, &encoded, r[7], 0, r[8])?;
                machine.set_register(7, encoded.len() as u64);
            }
            op::NOW => machine.set_register(7, self.base.time),
            op::RANDOM => {
                let bytes = random(&self.base.seed, self.step, self.draws);
                self.draws += 1;
                write(machine, r[7], &bytes)?;
                machine.set_register(7, code::OK);
            }
            op::SELF_ID => {
                machine.set_register(7, u64::from(instance.0));
                machine.set_register(8, u64::from(self.base.agent.0));
            }
            op::GET => {
                let key = key(machine, instance, r[7], r[8])?;
                match self.read_state(&key)? {
                    Some(value) => {
                        copy_out(machine, &value, r[9], r[10], r[11])?;
                        machine.set_register(7, value.len() as u64);
                    }
                    None => machine.set_register(7, code::NONE),
                }
            }
            op::PUT | op::DELETE => {
                let key = key(machine, instance, r[7], r[8])?;
                let value = if id == op::PUT {
                    Some(read(machine, r[9], r[10], cap::VALUE)?)
                } else {
                    None
                };
                self.written += key.len() + value.as_ref().map_or(0, Vec::len);
                if self.written > cap::STEP_WRITES {
                    return Err(failure::CAP);
                }
                self.frames.last_mut().expect("a frame").insert(key, value);
                machine.set_register(7, code::OK);
            }
            op::SCAN => {
                let prefix = key(machine, instance, r[7], r[8])?;
                let cursor = read(machine, r[9], r[10], cap::KEY)?;
                let base = keys::instance_prefix(instance);
                let after = (!cursor.is_empty()).then(|| [base.as_slice(), &cursor].concat());
                let capacity = (r[12] as usize).min(cap::SCAN);
                let (out, full) = self.scan(&prefix, after, capacity, base.len())?;
                write(machine, r[11], &out)?;
                machine.set_register(7, if full { code::FULL } else { out.len() as u64 });
            }
            op::CALL => {
                let callee = InstanceId(r[7] as u32);
                let method = MethodId(r[8] as u32);
                let call_arguments = read(machine, r[9], r[10], cap::REQUEST)?;
                let callee_kind = self
                    .installed(callee)?
                    .schema
                    .method(method)
                    .map(|schema| schema.kind)
                    .ok_or(failure::UNKNOWN)?;
                if callee_kind == Kind::Attestable
                    || (kind == Kind::Query && callee_kind != Kind::Query)
                {
                    return Err(failure::TRAPPED);
                }
                self.frames.push(BTreeMap::new());
                let effects = (self.messages.len(), self.attests.len(), self.written);
                let gas = machine.gas();
                let (ended, used) = self
                    .invoke(
                        Principal::Instance(instance),
                        callee,
                        method,
                        &call_arguments,
                        gas,
                    )
                    .map_err(|(code, _)| code)?;
                let frame = self.frames.pop().expect("the call's frame");
                *self.nested.last_mut().expect("the caller's entry") += used;
                if !machine.charge(used) {
                    return Err(failure::OUT_OF_GAS);
                }
                let (bytes, status) = match ended {
                    Ended::Replied(reply) => {
                        self.frames.last_mut().expect("a frame").extend(frame);
                        (reply, 0)
                    }
                    Ended::Failed(detail) => (detail, failure::HANDLER),
                    Ended::Forbidden => (Vec::new(), failure::FORBIDDEN),
                };
                if status != 0 {
                    let (messages, attests, written) = effects;
                    self.messages.truncate(messages);
                    self.attests.truncate(attests);
                    self.written = written;
                }
                copy_out(machine, &bytes, r[11], 0, r[12])?;
                machine.set_register(7, bytes.len() as u64);
                machine.set_register(8, u64::from(status));
            }
            op::SEND => {
                let call_arguments = read(machine, r[10], r[11], cap::MESSAGE)?;
                if self.messages.len() == cap::MESSAGES {
                    return Err(failure::CAP);
                }
                self.messages.push(Outgoing {
                    to: AgentId(r[7] as u32),
                    instance: InstanceId(r[8] as u32),
                    method: MethodId(r[9] as u32),
                    arguments: call_arguments,
                });
                machine.set_register(7, code::OK);
            }
            op::ATTEST => {
                let method = MethodId(r[7] as u32);
                let call_arguments = read(machine, r[8], r[9], cap::REQUEST)?;
                if self.attests.len() == cap::ATTESTS {
                    return Err(failure::CAP);
                }
                let program = installed.attestable(method).ok_or(failure::UNKNOWN)?;
                let gas = machine.gas();
                let (output, used) = attestable(&program, &call_arguments, gas)?;
                if !machine.charge(used) {
                    return Err(failure::OUT_OF_GAS);
                }
                self.attests.push(Attest {
                    program,
                    arguments: call_arguments,
                    output: output.clone(),
                });
                copy_out(machine, &output, r[10], 0, r[11])?;
                machine.set_register(7, output.len() as u64);
                machine.set_register(8, 0);
            }
            _ => unreachable!("served operations are known"),
        }
        Ok(())
    }

    /// A value through the call frames, the step's committed writes and
    /// applied state.
    fn read_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return Ok(value.clone());
            }
        }
        self.base.read(key)
    }

    /// Rows under `prefix`, after `after` when given, merged through
    /// every overlay and packed until `capacity`, with keys relative to
    /// the instance (`strip` bytes off); and whether the first row alone
    /// did not fit. The sources are walked in key order and the walk stops
    /// when the buffer is full, so a scan costs the rows it returns, not
    /// the overlays' size.
    fn scan(
        &self,
        prefix: &[u8],
        mut after: Option<Vec<u8>>,
        capacity: usize,
        strip: usize,
    ) -> Result<(Vec<u8>, bool), Corrupt> {
        use core::ops::Bound;
        let mut out = Vec::new();
        loop {
            // A page of applied rows bounds which overlay rows join it; an
            // empty page means no applied rows remain, so all of them do.
            let page = applied_rows(prefix, after.as_deref().unwrap_or(&[]))?;
            let bound = page.last().map(|(key, _)| key.as_slice());
            // A cursor below the prefix starts the scan at the prefix, as
            // the node's applied rows do; one above it leaves no row.
            let lower = match &after {
                Some(after) if after.as_slice() >= prefix => Bound::Excluded(after.as_slice()),
                _ => Bound::Included(prefix),
            };
            let joins =
                |key: &[u8]| key.starts_with(prefix) && bound.is_none_or(|bound| key <= bound);
            // Lowest precedence first: the refine's committed writes, then
            // each frame up the stack.
            let mut overlays: Vec<_> = core::iter::once(&self.base.committed)
                .chain(self.frames.iter())
                .map(|overlay| {
                    overlay
                        .range::<[u8], _>((lower, Bound::Unbounded))
                        .take_while(|(key, _)| joins(key))
                        .peekable()
                })
                .collect();
            let mut applied = page.iter().peekable();
            loop {
                let mut next = applied.peek().map(|(key, _)| key.as_slice());
                for overlay in &mut overlays {
                    if let Some((key, _)) = overlay.peek()
                        && next.is_none_or(|next| key.as_slice() < next)
                    {
                        next = Some(key.as_slice());
                    }
                }
                let Some(key) = next.map(<[u8]>::to_vec) else {
                    break;
                };
                // The highest source holding the key decides its value.
                let mut value: Option<Option<&[u8]>> = None;
                for overlay in overlays.iter_mut().rev() {
                    if overlay.peek().is_some_and(|(head, _)| **head == key) {
                        let (_, held) = overlay.next().expect("peeked");
                        value.get_or_insert(held.as_deref());
                    }
                }
                if applied.peek().is_some_and(|(head, _)| *head == key) {
                    let (_, held) = applied.next().expect("peeked");
                    value.get_or_insert(Some(held));
                }
                let Some(Some(value)) = value else { continue };
                let relative = &key[strip..];
                if out.len() + 8 + relative.len() + value.len() > capacity {
                    let full = out.is_empty();
                    return Ok((out, full));
                }
                (relative.len() as u32).encode_to(&mut out);
                out.extend_from_slice(relative);
                (value.len() as u32).encode_to(&mut out);
                out.extend_from_slice(value);
            }
            match bound {
                Some(bound) => after = Some(bound.to_vec()),
                None => return Ok((out, false)),
            }
        }
    }
}

fn known(id: u64) -> bool {
    matches!(
        id,
        op::INPUT
            | op::REPLY
            | op::FAIL
            | op::LOG
            | op::CALLER
            | op::NOW
            | op::RANDOM
            | op::GET
            | op::PUT
            | op::DELETE
            | op::SCAN
            | op::CALL
            | op::SEND
            | op::ATTEST
            | op::SELF_ID
    )
}

/// `RANDOM`'s bytes: BLAKE2b-256 of `vos/random`, the seed, the step's
/// index and the draws before.
fn random(seed: &[u8; 32], step: u32, draw: u64) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/random",
        &[seed, &step.to_le_bytes(), &draw.to_le_bytes()],
    )
}

/// Run an attestable program in its own machine: arguments in the standard
/// window, output by the halt convention, no host calls (the node serves
/// precompiles in place).
fn attestable(program: &ProgramHash, arguments: &[u8], gas: u64) -> Result<(Vec<u8>, u64), u32> {
    let mut machine = Machine::acquire(&program.0).map_err(|unavailable| match unavailable {
        Unavailable::Full => failure::DEPTH,
        Unavailable::Missing => failure::UNKNOWN,
    })?;
    if !machine.map_read_only(ARGUMENTS, arguments.len() as u64, arguments) {
        return Err(failure::TRAPPED);
    }
    machine.set_gas(gas);
    machine.set_register(7, ARGUMENTS);
    machine.set_register(8, arguments.len() as u64);
    match machine.invoke() {
        Exit::Halt => {
            let used = gas - machine.gas();
            let len = machine.register(8) as usize;
            if len > cap::REPLY {
                return Err(failure::CAP);
            }
            let output = machine.peek(machine.register(7), len).ok_or(failure::CAP)?;
            Ok((output, used))
        }
        Exit::OutOfGas => Err(failure::OUT_OF_GAS),
        _ => Err(failure::TRAPPED),
    }
}

/// The agent-relative key for the instance-relative key at `address`.
fn key(
    machine: &mut Machine,
    instance: InstanceId,
    address: u64,
    len: u64,
) -> Result<Vec<u8>, u32> {
    let relative = read(machine, address, len, cap::KEY)?;
    if relative.is_empty() {
        return Err(failure::TRAPPED);
    }
    Ok([keys::instance_prefix(instance), relative].concat())
}

/// The actor's bytes, at most `limit`: a longer buffer exceeds a cap and
/// an unreadable one traps.
fn read(machine: &mut Machine, address: u64, len: u64, limit: usize) -> Result<Vec<u8>, u32> {
    let len = usize::try_from(len).map_err(|_| failure::CAP)?;
    if len > limit {
        return Err(failure::CAP);
    }
    if !machine.charge(len as u64 * price::PER_BYTE) {
        return Err(failure::OUT_OF_GAS);
    }
    machine.peek(address, len).ok_or(failure::TRAPPED)
}

fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), u32> {
    if !machine.charge(bytes.len() as u64 * price::PER_BYTE) {
        return Err(failure::OUT_OF_GAS);
    }
    if machine.poke(address, bytes) {
        Ok(())
    } else {
        Err(failure::TRAPPED)
    }
}

fn copy_out(
    machine: &mut Machine,
    bytes: &[u8],
    address: u64,
    offset: u64,
    capacity: u64,
) -> Result<(), u32> {
    let offset = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let len = usize::try_from(capacity)
        .unwrap_or(usize::MAX)
        .min(bytes.len() - offset);
    write(machine, address, &bytes[offset..offset + len])
}
