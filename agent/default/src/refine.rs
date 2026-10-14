//! Refine: a batch's inputs as steps, each an actor invocation served
//! against overlays of this refine's writes, or a query on applied state.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use vos_wire::abi::{self, Failure, Kind, Refusal, Rows, cap, code, op, precompile, price};
use vos_wire::batch::{Admin, Await, Batch, Body, Input, Message, Query, Request, Work};
use vos_wire::ids::{
    AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, SessionId, SessionRef,
};
use vos_wire::jam::RefineArgs;
use vos_wire::keys::Transform;
use vos_wire::records::{Installed, SessionMark, unstored, unversioned};
use vos_wire::result::{
    Attest, CommittedWrite, InputRef, InstanceGas, Outcome, Outgoing, ResultWriter, Run, Step,
    Write,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, expiry, keys};

use crate::host::{STATE_SCAN, ecalli, gas, ptr, state_read, state_read_into, unserved};
use crate::machines::{ARGUMENTS, Exit, Machine, Unavailable};

/// Nested invocations a step may hold at once.
const MAX_DEPTH: usize = 63;
/// Applied rows fetched per `state_scan` at first; a page grows to
/// [`cap::STORED_ROW`], room for the largest row, when a row needs it.
const SCAN_PAGE: usize = 4096;
/// Where a program's schema starts: the read-only zone.
const SCHEMA_AT: u64 = 1 << 16;

type Overlay = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
/// Rows of state, each a key and its value, in key order.
type StateRows = Vec<(Vec<u8>, Vec<u8>)>;

pub fn run(arguments: &[u8]) -> Vec<u8> {
    let arguments = RefineArgs::decode(arguments).expect("refine arguments");
    let (work, _) = Work::decode(&arguments.payload).expect("a work item");
    let agent = AgentId(arguments.service as u32);
    match work {
        Work::Batch(batch) => run_batch(agent, batch),
        Work::Query(query) => run_query(agent, query).encode(),
    }
}

/// The refine's gas as the agent accounts for it, from the batch and state
/// alone, never from `gas`, whose readings differ between hosts: what the
/// batch's budget leaves once the dispatched steps are taken. So every host
/// dispatches the same steps.
struct Meter {
    left: Cell<u64>,
    /// What the running step keeps of `left`: its reserve, its handler's
    /// limit and the finish. The installed records it reads first and its
    /// served precompiles take from above it.
    kept: Cell<u64>,
    /// A charge found nothing above `kept`.
    overrun: Cell<bool>,
}

impl Meter {
    fn new(left: u64) -> Self {
        Self {
            left: Cell::new(left),
            kept: Cell::new(0),
            overrun: Cell::new(false),
        }
    }

    /// Take `gas` before the agent spends it; false, the step overrun, when
    /// what lies above what the step keeps cannot pay it.
    fn take(&self, gas: u64) -> bool {
        match self.left.get().checked_sub(gas) {
            Some(left) if left >= self.kept.get() => {
                self.left.set(left);
                true
            }
            _ => {
                self.overrun.set(true);
                false
            }
        }
    }
}

/// A stored value without its format byte, or an agent record that does
/// not decode: state the agent did not write. It fails the step that reads
/// it, so one bad row cannot stop the agent.
#[derive(Clone, Copy, Debug)]
struct Corrupt;

impl From<Corrupt> for Failure {
    fn from(_: Corrupt) -> Failure {
        Failure::Trapped
    }
}

/// The value stored under `key`: without its format byte, and, in a
/// committed map's value row, without the version that wrote it.
fn stored_value<'a>(key: &[u8], bytes: &'a [u8]) -> Result<&'a [u8], Corrupt> {
    let value = unstored(bytes).ok_or(Corrupt)?;
    if keys::is_committed(key) {
        unversioned(value).map(|(_, value)| value).ok_or(Corrupt)
    } else {
        Ok(value)
    }
}

/// A value of applied state, by agent-relative key.
fn applied(key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
    state_read(key)
        .map(|bytes| stored_value(key, &bytes).map(<[u8]>::to_vec))
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
    // Every record refine reads fits, the stored byte included (a session
    // mark takes 17 bytes); a larger one is read again whole.
    let mut small = [0u8; 32];
    match state_read_into(key, &mut small) {
        None => Ok(None),
        Some(len) if len <= small.len() => decode(&small[..len]),
        Some(_) => state_read(key).map_or(Ok(None), |bytes| decode(&bytes)),
    }
}

/// Applied rows under `prefix` after `after`, a page at a time.
fn applied_rows(prefix: &[u8], after: &[u8]) -> Result<StateRows, Corrupt> {
    scan_page(prefix, after)
        .into_iter()
        .map(|(key, value)| {
            let value = stored_value(&key, &value)?.to_vec();
            Ok((key, value))
        })
        .collect()
}

/// A page of rows under `prefix` after `after`, their values as stored.
fn scan_page(prefix: &[u8], after: &[u8]) -> StateRows {
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
                assert!(capacity < cap::STORED_ROW, "a stored row past its cap");
                capacity = cap::STORED_ROW;
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
        let (row, used) = <(Vec<u8>, Vec<u8>)>::decode(&out[at..]).expect("a row");
        at += used;
        rows.push(row);
    }
    rows
}

/// What one refine has committed so far, above applied state.
struct Base {
    agent: AgentId,
    time: u64,
    seed: [u8; 32],
    meter: Meter,
    /// Writes of the steps already committed in this refine, in order.
    earlier: Overlay,
    /// Installed records read in this refine. Only admin steps change
    /// them, and they clear it.
    installed: RefCell<BTreeMap<InstanceId, Option<Rc<Installed>>>>,
}

impl Base {
    /// A value through this refine's earlier steps and applied state.
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        match self.earlier.get(key) {
            Some(value) => Ok(value.clone()),
            None => applied(key),
        }
    }

    /// An instance's installed record. Read the first time in a refine, it
    /// is paid first, by its length ([`defaults::RECORD_BYTE`]): out of gas
    /// when the meter cannot pay it.
    fn installed(&self, instance: InstanceId) -> Result<Option<Rc<Installed>>, Failure> {
        if let Some(cached) = self.installed.borrow().get(&instance) {
            return Ok(cached.clone());
        }
        let key = keys::installed(instance);
        let len = match self.earlier.get(&key) {
            Some(value) => value.as_ref().map_or(0, Vec::len),
            None => state_read_into(&key, &mut []).unwrap_or(0),
        };
        if !self.meter.take(defaults::RECORD_BYTE * len as u64) {
            return Err(Failure::OutOfGas);
        }
        let installed = match self.read(&key)? {
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

/// A request's session as this refine sees it.
#[derive(Clone, Copy)]
enum Held {
    /// Neither the state holds it nor has a step created it.
    Absent,
    /// An earlier step of this refine created it: it has no id yet.
    New(SessionMark),
    /// The state holds it, under its id.
    Known(SessionId, SessionMark),
}

impl Held {
    fn mark(self) -> Option<SessionMark> {
        match self {
            Held::Absent => None,
            Held::New(mark) | Held::Known(_, mark) => Some(mark),
        }
    }

    /// The session once a step has run at `mark`.
    fn advanced(self, mark: SessionMark) -> Held {
        match self {
            Held::Known(id, _) => Held::Known(id, mark),
            Held::Absent | Held::New(_) => Held::New(mark),
        }
    }
}

/// A session as the in-batch map orders it: by its name as a number
/// first, then its time, then its key, so sessions compare in a few
/// instructions and one key's many sessions differ at once.
type ByName = (u128, u64, [u8; 32]);

fn by_name(session: &Session) -> ByName {
    (u128::from_le_bytes(session.name), session.t0, session.key)
}

/// The sessions the agent holds, in all and per key, as this refine has
/// created them so far: the applied counts, each read once, and the
/// batch's.
#[derive(Default)]
struct Counts {
    live: Option<u64>,
    keys: BTreeMap<[u8; 32], u64>,
}

impl Counts {
    /// The cap a new session of `key` would pass, if any.
    fn full(&mut self, key: &[u8; 32]) -> Result<Option<Refusal>, Corrupt> {
        let live = match self.live {
            Some(live) => live,
            None => *self
                .live
                .insert(record::<u64>(&keys::live_sessions())?.unwrap_or(0)),
        };
        if live >= defaults::MAX_SESSIONS {
            return Ok(Some(Refusal::SessionsFull));
        }
        let held = match self.keys.get(key) {
            Some(held) => *held,
            None => {
                let held = record::<u64>(&keys::key_sessions(key))?.unwrap_or(0);
                self.keys.insert(*key, held);
                held
            }
        };
        Ok((held >= defaults::MAX_KEY_SESSIONS).then_some(Refusal::KeySessionsFull))
    }

    /// A new session of `key`, which [`Counts::full`] let through.
    fn add(&mut self, key: &[u8; 32]) {
        *self.live.as_mut().expect("the live count") += 1;
        *self.keys.get_mut(key).expect("the key's count") += 1;
    }
}

/// A session as applied state holds it.
fn held(session: &Session) -> Result<Held, Corrupt> {
    match record::<SessionId>(&keys::session_index_key(session))? {
        Some(id) => {
            let mark = record::<SessionMark>(&keys::session(id))?.ok_or(Corrupt)?;
            Ok(Held::Known(id, mark))
        }
        None => Ok(Held::Absent),
    }
}

/// A request against its session as this refine sees it: how the result
/// names the session, and the session before the step, or the code that
/// refuses the step. A session the step would create must fit the caps;
/// it counts toward them once the step is in the result ([`Counts::add`]).
fn admit(
    base: &Base,
    sessions: &BTreeMap<ByName, Held>,
    counts: &mut Counts,
    request: &Request,
) -> (InputRef, Result<Held, Refusal>) {
    let held = match sessions.get(&by_name(&request.session)) {
        Some(held) => Ok(*held),
        None => held(&request.session),
    };
    // A session the state does not hold names itself whole.
    let session = match held {
        Ok(Held::Known(id, _)) => SessionRef::Known(id),
        _ => SessionRef::New(alloc::boxed::Box::new(request.session)),
    };
    let input = InputRef::Request {
        session,
        sequence: request.sequence,
    };
    let Ok(held) = held else {
        return (input, Err(Refusal::Unreadable));
    };
    let admitted = match held.mark() {
        // A duplicate first, even in an expired session: the leader
        // answers it from the window.
        Some(mark) if request.sequence <= mark.sequence => Err(Refusal::Sequence),
        Some(mark) if base.time > mark.time.saturating_add(defaults::SESSION_EXPIRY_MS) => {
            Err(Refusal::Expired)
        }
        Some(mark) if request.sequence != mark.sequence + 1 => Err(Refusal::Sequence),
        Some(_) => Ok(held),
        None if request.session.t0.abs_diff(base.time) > defaults::SESSION_SKEW_MS => {
            Err(Refusal::StaleSession)
        }
        None if request.sequence != 1 => Err(Refusal::Sequence),
        // Neither held nor created by an earlier step: this one creates
        // it, within the caps.
        None => match counts.full(&request.session.key) {
            Ok(None) => Ok(held),
            Ok(Some(code)) => Err(code),
            Err(Corrupt) => Err(Refusal::Unreadable),
        },
    };
    (input, admitted)
}

/// Run a batch's inputs as steps, within its budget.
fn run_batch(agent: AgentId, batch: Batch) -> Vec<u8> {
    // The one reading of `gas`. A node gives a refine its batch's budget and
    // what decoding the batch may take (`defaults::refine_start`), so the
    // budget is left now; a refine given less traps rather than run out
    // partway, and nothing else depends on the reading.
    assert!(
        gas() >= batch.budget,
        "the refine's gas does not cover its budget"
    );
    let mut base = Base {
        agent,
        time: batch.time,
        seed: batch.seed,
        meter: Meter::new(batch.budget),
        earlier: BTreeMap::new(),
        installed: RefCell::new(BTreeMap::new()),
    };
    let mut sessions: BTreeMap<ByName, Held> = BTreeMap::new();
    let mut pairs: BTreeMap<AgentId, u64> = BTreeMap::new();
    let mut counts = Counts::default();
    let mut result = ResultWriter::new(batch.version, batch.time, batch.seed);
    // Whether a step in the result ran a handler.
    let mut handled = false;
    for (index, input) in batch.inputs.into_iter().enumerate() {
        let index = index as u32;
        // Dispatch only what the budget can finish, by the meter: the
        // input's reserve first, then its handler's limit, once its
        // installed record, paid for above the reserve, gives it.
        let handler = matches!(
            &input,
            Input::Request(_)
                | Input::Message(Message {
                    body: Body::Call { .. },
                    ..
                })
        );
        let reserve = match input {
            _ if handler => defaults::STEP_RESERVE,
            Input::Admin(_) => defaults::INSTALL_RESERVE,
            Input::Sweep => defaults::SWEEP_RESERVE,
            _ => defaults::INPUT_RESERVE,
        };
        base.meter.kept.set(reserve + defaults::FINISH_RESERVE);
        if base.meter.left.get() < base.meter.kept.get() {
            break;
        }
        let limit = match &input {
            Input::Request(request) => limit(&base, request.instance, request.method),
            Input::Message(Message {
                body: Body::Call {
                    instance, method, ..
                },
                ..
            }) => limit(&base, *instance, *method),
            _ => Some(0),
        };
        let Some(limit) = limit else {
            break;
        };
        let kept = reserve + limit + defaults::FINISH_RESERVE;
        if base.meter.left.get() < kept {
            break;
        }
        base.meter.kept.set(kept);
        let admin = matches!(input, Input::Admin(_));
        // The key of a session this step creates.
        let mut creates = None;
        let (step, mark) = match input {
            Input::Request(request) => match admit(&base, &sessions, &mut counts, &request) {
                (input, Err(code)) => (Step::Refused { input, code }, None),
                (input, Ok(held)) => {
                    if let Held::Absent = held {
                        creates = Some(request.session.key);
                    }
                    let step = Step::Ran(command(
                        &base,
                        index,
                        input,
                        request.caller,
                        request.instance,
                        request.method,
                        &request.arguments,
                    ));
                    let mark = SessionMark {
                        sequence: request.sequence,
                        time: base.time,
                    };
                    (
                        step,
                        Some(Mark::Session(request.session, held.advanced(mark))),
                    )
                }
            },
            Input::Message(message) => self::message(&base, &pairs, index, message),
            Input::Failed {
                from,
                sequence,
                awaiting,
            } => failed_in_refine(&pairs, from, sequence, awaiting),
            Input::Admin(admin) => (self::admin(admin), None),
            Input::Ack { to, sequence } => (acknowledge(to, sequence), None),
            Input::Sweep => (sweep(base.time), None),
        };
        // A step that overran the budget, reading records or serving
        // precompiles, waits with every later input for the next batch
        // behind a step that ran a handler. With none before it, only inputs
        // that run none came first, a sweep or acknowledgements, which leave
        // it as little room in any batch: it fails, consumed. A step the
        // result cannot hold waits too; one alone always fits
        // (`cap::STEP_RESULT`).
        if (base.meter.overrun.get() && handled) || !result.push(&step) {
            break;
        }
        base.meter.overrun.set(false);
        handled |= handler && matches!(step, Step::Ran(_));
        let used = match &step {
            Step::Ran(run) => run.gas_used,
            _ => 0,
        };
        base.meter.left.set(base.meter.left.get() - reserve - used);
        if let Some(key) = creates {
            counts.add(&key);
        }
        if let Step::Ran(run) = &step {
            for write in &run.writes {
                base.earlier.insert(write.key.clone(), write.value.clone());
            }
            for write in &run.committed {
                let key = keys::committed(&write.map, &write.key);
                base.earlier.insert(key, write.value.clone());
            }
        }
        if admin {
            // An admin step may change installed records.
            base.installed.borrow_mut().clear();
        }
        match mark {
            Some(Mark::Session(session, held)) => {
                sessions.insert(by_name(&session), held);
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
/// will fail before running. `None` when the meter cannot pay the installed
/// record that gives it.
fn limit(base: &Base, instance: InstanceId, method: MethodId) -> Option<u64> {
    let installed = match base.installed(instance) {
        Err(Failure::OutOfGas) => return None,
        installed => installed.ok().flatten(),
    };
    Some(
        installed
            .and_then(|installed| installed.schema.method(method).map(|schema| schema.gas))
            .map_or(0, |gas| {
                gas.unwrap_or(defaults::HANDLER_GAS)
                    .min(defaults::MAX_HANDLER_GAS)
            }),
    )
}

/// Why a message from `from` at `sequence` is out of its pair's order, if
/// it is.
fn out_of_order(pairs: &BTreeMap<AgentId, u64>, from: AgentId, sequence: u64) -> Option<Refusal> {
    let mark = match pairs.get(&from) {
        Some(mark) => Ok(Some(*mark)),
        None => record::<u64>(&keys::pair_in(from)),
    };
    match mark {
        Err(Corrupt) => Some(Refusal::Unreadable),
        Ok(mark) if sequence != mark.unwrap_or(0) + 1 => Some(Refusal::Sequence),
        Ok(_) => None,
    }
}

/// A message in its pair's order: a call runs as a command of the
/// sending agent's, and a reply is consumed with no await to resume. A
/// call that awaits gets its reply among the step's messages, whatever
/// its outcome.
fn message(
    base: &Base,
    pairs: &BTreeMap<AgentId, u64>,
    index: u32,
    message: Message,
) -> (Step, Option<Mark>) {
    let (from, sequence) = (message.from, message.sequence);
    let input = InputRef::Message { from, sequence };
    if let Some(code) = out_of_order(pairs, from, sequence) {
        return (Step::Refused { input, code }, None);
    }
    let (run, awaiting) = match message.body {
        Body::Call {
            instance,
            method,
            arguments,
            awaiting,
        } => {
            let caller = Principal::Agent(from);
            let run = command(base, index, input, caller, instance, method, &arguments);
            (run, awaiting)
        }
        Body::Reply { .. } => (consumed(input, Outcome::Done(Vec::new())), None),
    };
    let run = answered(run, from, awaiting);
    (Step::Ran(run), Some(Mark::Pair(from, sequence)))
}

/// A message the leader asserts failed in refine, in its pair's order:
/// consumed as failed without running, and answered when it awaits.
fn failed_in_refine(
    pairs: &BTreeMap<AgentId, u64>,
    from: AgentId,
    sequence: u64,
    awaiting: Option<Await>,
) -> (Step, Option<Mark>) {
    let input = InputRef::Message { from, sequence };
    if let Some(code) = out_of_order(pairs, from, sequence) {
        return (Step::Refused { input, code }, None);
    }
    let outcome = Outcome::Failed {
        code: Failure::InRefine,
        detail: Vec::new(),
    };
    let run = answered(consumed(input, outcome), from, awaiting);
    (Step::Ran(run), Some(Mark::Pair(from, sequence)))
}

/// `run`, with the reply to agent `to`'s request awaiting at `awaiting`,
/// if any, after its own messages: the step's outcome.
fn answered(mut run: Run, to: AgentId, awaiting: Option<Await>) -> Run {
    if let Some(awaiting) = awaiting {
        let answer = run.outcome.clone().into();
        run.messages.push(Outgoing {
            to,
            body: Body::Reply { awaiting, answer },
        });
    }
    run
}

/// A consumed step that runs nothing.
fn consumed(input: InputRef, outcome: Outcome) -> Run {
    Run {
        input,
        outcome,
        instances: Vec::new(),
        writes: Vec::new(),
        committed: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        gas_used: 0,
    }
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
) -> Run {
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
    match outcome {
        Outcome::Done(reply) => {
            let overlay = frames.pop().expect("the step overlay");
            let (writes, committed) = split(overlay);
            Run {
                input,
                outcome: Outcome::Done(reply),
                instances,
                writes,
                committed,
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
            committed: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            gas_used,
        },
    }
}

/// A step's writes: those to committed maps apart, by map and transformed
/// key.
fn split(overlay: Overlay) -> (Vec<Write>, Vec<CommittedWrite>) {
    let mut writes = Vec::new();
    let mut committed = Vec::new();
    for (key, value) in overlay {
        if let Some((map, transformed)) = keys::committed_entry(&key) {
            committed.push(CommittedWrite {
                map,
                key: transformed.to_vec(),
                value,
            });
        } else {
            writes.push(Write { key, value });
        }
    }
    (writes, committed)
}

fn run_query(agent: AgentId, query: Query) -> Outcome {
    let base = Base {
        agent,
        time: query.time,
        seed: query.seed,
        // One invocation, within its handler's limit: nothing to dispatch.
        meter: Meter::new(u64::MAX),
        earlier: BTreeMap::new(),
        installed: RefCell::new(BTreeMap::new()),
    };
    let mut invocation = Invocation::new(&base, 0, Kind::Query);
    invocation.top(query.caller, query.instance, query.method, &query.arguments)
}

/// An acknowledgement from agent `to`: unsequenced, never refused, and
/// it runs no actor. Accumulate clears the outbox through `sequence`.
fn acknowledge(to: AgentId, sequence: u64) -> Step {
    Step::Ran(consumed(
        InputRef::Ack { to, sequence },
        Outcome::Done(Vec::new()),
    ))
}

/// The expiry rows due at `time`, oldest first, at most
/// [`defaults::SWEEP_LIMIT`]. Accumulate reads the sessions and decides;
/// a row whose key is not an expiry key is passed over.
fn sweep(time: u64) -> Step {
    let prefix = keys::expiry_prefix();
    let mut due = Vec::new();
    let mut after = Vec::new();
    'pages: loop {
        let rows = scan_page(&prefix, &after);
        let Some((last, _)) = rows.last() else {
            break;
        };
        after = last.clone();
        for (key, _) in &rows {
            let Some((bucket, session)) = keys::expiry_entry(key) else {
                continue;
            };
            if expiry::due(bucket) > time {
                break 'pages;
            }
            due.push((bucket, session));
            if due.len() == defaults::SWEEP_LIMIT {
                break 'pages;
            }
        }
    }
    Step::Swept { due }
}

/// An operator command: install a package or set a role. Its writes are
/// under the step write cap like any step's.
fn admin(admin: Admin) -> Step {
    let failed = |code| {
        Step::Ran(consumed(
            InputRef::Admin,
            Outcome::Failed {
                code,
                detail: Vec::new(),
            },
        ))
    };
    let write = match admin {
        Admin::Install {
            instance,
            program,
            beside,
            roles,
        } => {
            let Some(installed) = install(program, beside, roles) else {
                return failed(Failure::Unknown);
            };
            Write {
                key: keys::installed(instance),
                value: Some(installed.encode()),
            }
        }
        Admin::SetRole(grant) => Write {
            key: keys::member(&grant.principal),
            value: grant.role.map(|role| alloc::vec![role]),
        },
    };
    if write.key.len() + write.value.as_ref().map_or(0, Vec::len) > cap::STEP_WRITES {
        return failed(Failure::Cap);
    }
    Step::Ran(Run {
        input: InputRef::Admin,
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes: alloc::vec![write],
        committed: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        gas_used: 0,
    })
}

/// Read a program's schema from its machine and check the package: each
/// program beside the actor's is bound to a method of its kind, an
/// attestable or a workflow, every such method has exactly one, and every
/// role name is mapped.
fn install(
    program: ProgramHash,
    beside: Vec<(MethodId, Kind, ProgramHash)>,
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
        beside,
        roles,
        schema,
    };
    for &(method, kind, _) in &installed.beside {
        let schema = installed.schema.method(method)?;
        if schema.kind != kind || !has_own_program(kind) {
            return None;
        }
    }
    let mut own = 0;
    for method in &installed.schema.methods {
        if has_own_program(method.kind) {
            own += 1;
            installed.bound(method.id, method.kind)?;
        }
        if let Some(role) = &method.role
            && installed.role(role).is_none()
        {
            return None;
        }
    }
    // Each program is bound to such a method, and each such method has
    // one: as many as there are of them, no method has two.
    (installed.beside.len() == own).then_some(installed)
}

/// Whether a method of `kind` runs as its own program, bound at install,
/// never as a handler of the actor's.
fn has_own_program(kind: Kind) -> bool {
    matches!(kind, Kind::Attestable | Kind::Workflow)
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
            return failed(Failure::Cap);
        }
        let installed = match self.installed(instance) {
            Ok(installed) => installed,
            Err(code) => return failed(code),
        };
        let Some(schema) = installed.schema.method(method) else {
            return failed(Failure::Unknown);
        };
        if has_own_program(schema.kind) || (self.entry == Kind::Query && schema.kind != Kind::Query)
        {
            return failed(Failure::Unknown);
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
                        code: Failure::Handler,
                        detail,
                    },
                    Ended::Forbidden => failed(Failure::Forbidden),
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
    ) -> Result<(Ended, u64), (Failure, u64)> {
        let installed = self.installed(instance).map_err(|code| (code, 0))?;
        let schema = installed
            .schema
            .method(method)
            .ok_or((Failure::Unknown, 0))?;
        if let Some(role) = &schema.role {
            let required = installed.role(role).expect("checked at install");
            if self.role(&caller).map_err(|_| (Failure::Trapped, 0))? != Some(required) {
                return Ok((Ended::Forbidden, 0));
            }
        }
        if self.stack.contains(&instance) {
            return Err((Failure::Cycle, 0));
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err((Failure::Depth, 0));
        }
        let kind = schema.kind;
        let mut machine =
            Machine::acquire(&installed.program.0).map_err(|unavailable| match unavailable {
                Unavailable::Full => (Failure::Depth, 0),
                Unavailable::Missing => (Failure::Unknown, 0),
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
    fn installed(&self, instance: InstanceId) -> Result<Rc<Installed>, Failure> {
        self.base.installed(instance)?.ok_or(Failure::Unknown)
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
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        loop {
            match machine.invoke() {
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::OutOfGas => return Err(Failure::OutOfGas),
                Exit::Panic | Exit::Fault(_) => return Err(Failure::Trapped),
                Exit::Host(id) if precompile::price(id).is_some() => {
                    serve_precompile(&self.base.meter, machine, id)?;
                }
                Exit::Host(id) => {
                    if !known(id) {
                        if !machine.charge(price::OPERATION) {
                            return Err(Failure::OutOfGas);
                        }
                        machine.set_register(7, code::WHAT);
                        continue;
                    }
                    if !abi::allowed(kind, id) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(id)) {
                        return Err(Failure::OutOfGas);
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
    ) -> Result<(), Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        match id {
            op::INPUT => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.set_register(7, arguments.len() as u64);
            }
            op::REPLY | op::FAIL => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
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
                let key = row(machine, instance, r[7], r[8], r[9])?;
                match self.read_state(&key)? {
                    Some(value) => {
                        copy_out(machine, &value, r[10], r[11], r[12])?;
                        machine.set_register(7, value.len() as u64);
                    }
                    None => machine.set_register(7, code::NONE),
                }
            }
            op::PUT | op::DELETE => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                let value = if id == op::PUT {
                    Some(read(machine, r[10], r[11], cap::VALUE)?)
                } else {
                    None
                };
                self.written += key.len() + value.as_ref().map_or(0, Vec::len);
                if self.written > cap::STEP_WRITES {
                    return Err(Failure::Cap);
                }
                self.frames.last_mut().expect("a frame").insert(key, value);
                machine.set_register(7, code::OK);
            }
            op::SCAN => {
                let cursor = match r[12] {
                    0 => None,
                    1 => Some(read_key(machine, r[8], r[9])?),
                    _ => return Err(Failure::Trapped),
                };
                let rows = Rows::from_register(r[7]).ok_or(Failure::Trapped)?;
                let (prefix, transform) =
                    keys::rows_prefix(instance, rows).ok_or(Failure::Trapped)?;
                let after = cursor
                    .map(|cursor| keys::row(instance, rows, &cursor))
                    .transpose()?;
                let capacity = (r[11] as usize).min(cap::SCAN);
                let (out, full, returned) = self.scan(&prefix, after, capacity, transform)?;
                if !machine.charge(returned as u64 * price::KEY_BYTE) {
                    return Err(Failure::OutOfGas);
                }
                write(machine, r[10], &out)?;
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
                    .ok_or(Failure::Unknown)?;
                if has_own_program(callee_kind)
                    || (kind == Kind::Query && callee_kind != Kind::Query)
                {
                    return Err(Failure::Trapped);
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
                    return Err(Failure::OutOfGas);
                }
                let (bytes, failed) = match ended {
                    Ended::Replied(reply) => {
                        self.frames.last_mut().expect("a frame").extend(frame);
                        (reply, None)
                    }
                    Ended::Failed(detail) => (detail, Some(Failure::Handler)),
                    Ended::Forbidden => (Vec::new(), Some(Failure::Forbidden)),
                };
                if failed.is_some() {
                    let (messages, attests, written) = effects;
                    self.messages.truncate(messages);
                    self.attests.truncate(attests);
                    self.written = written;
                }
                copy_out(machine, &bytes, r[11], 0, r[12])?;
                machine.set_register(7, bytes.len() as u64);
                machine.set_register(8, failed.map_or(0, |code| code.code().into()));
            }
            op::SEND => {
                let call_arguments = read(machine, r[10], r[11], cap::MESSAGE)?;
                if self.messages.len() == cap::MESSAGES {
                    return Err(Failure::Cap);
                }
                self.messages.push(Outgoing {
                    to: AgentId(r[7] as u32),
                    body: Body::Call {
                        instance: InstanceId(r[8] as u32),
                        method: MethodId(r[9] as u32),
                        arguments: call_arguments,
                        awaiting: None,
                    },
                });
                machine.set_register(7, code::OK);
            }
            op::ATTEST => {
                let method = MethodId(r[7] as u32);
                let call_arguments = read(machine, r[8], r[9], cap::REQUEST)?;
                if self.attests.len() == cap::ATTESTS {
                    return Err(Failure::Cap);
                }
                let program = installed.attestable(method).ok_or(Failure::Unknown)?;
                let gas = machine.gas();
                let (output, used) = attestable(&self.base.meter, &program, &call_arguments, gas)?;
                if !machine.charge(used) {
                    return Err(Failure::OutOfGas);
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

    /// A value through the call frames, the refine's earlier steps and
    /// applied state.
    fn read_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return Ok(value.clone());
            }
        }
        self.base.read(key)
    }

    /// The rows of the table at `prefix`, after `after` when given, merged
    /// through every overlay and packed until `capacity`, each with the
    /// key its `transform` was given; whether the first row alone did not
    /// fit; and the bytes of the keys returned. The sources are walked in
    /// key order and the walk stops
    /// when the buffer is full, so a scan costs the rows it returns, not
    /// the overlays' size.
    fn scan(
        &self,
        prefix: &[u8],
        mut after: Option<Vec<u8>>,
        capacity: usize,
        transform: Transform,
    ) -> Result<(Vec<u8>, bool, usize), Corrupt> {
        use core::ops::Bound;
        let mut out = Vec::new();
        let mut returned = 0;
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
            // Lowest precedence first: the refine's earlier steps' writes,
            // then each frame up the stack.
            let mut overlays: Vec<_> = core::iter::once(&self.base.earlier)
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
                let mut next = applied.peek().copied().map(|(key, _)| key.as_slice());
                for overlay in &mut overlays {
                    if let Some(&(key, _)) = overlay.peek()
                        && next.is_none_or(|next| key.as_slice() < next)
                    {
                        next = Some(key.as_slice());
                    }
                }
                let Some(key) = next else {
                    break;
                };
                // The source the key came from holds it without a compare:
                // keys here run to kilobytes.
                let holds = |head: &[u8]| core::ptr::eq(head, key) || head == key;
                // The highest source holding the key decides its value.
                let mut value: Option<Option<&[u8]>> = None;
                for overlay in overlays.iter_mut().rev() {
                    if overlay.peek().is_some_and(|&(head, _)| holds(head)) {
                        let (_, held) = overlay.next().expect("peeked");
                        value.get_or_insert(held.as_deref());
                    }
                }
                if applied.peek().is_some_and(|(head, _)| holds(head)) {
                    let (_, held) = applied.next().expect("peeked");
                    value.get_or_insert(Some(held));
                }
                let Some(Some(value)) = value else { continue };
                let raw = transform.raw(&key[prefix.len()..]).ok_or(Corrupt)?;
                if out.len() + 8 + raw.len() + value.len() > capacity {
                    let full = out.is_empty();
                    return Ok((out, full, returned));
                }
                returned += raw.len();
                (raw.len() as u32).encode_to(&mut out);
                out.extend_from_slice(&raw);
                (value.len() as u32).encode_to(&mut out);
                out.extend_from_slice(value);
            }
            match bound {
                Some(bound) => after = Some(bound.to_vec()),
                None => return Ok((out, false, returned)),
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

/// Serve a machine's precompile call, accounting for the agent's serving
/// on the meter first.
fn serve_precompile(meter: &Meter, machine: &mut Machine, id: u64) -> Result<(), Failure> {
    if !meter.take(defaults::PRECOMPILE_SERVING) {
        return Err(Failure::OutOfGas);
    }
    machine.precompile(id)
}

/// Run an attestable program in its own machine: arguments in the standard
/// window, output by the halt convention, and no host calls but
/// precompiles, which the agent serves.
fn attestable(
    meter: &Meter,
    program: &ProgramHash,
    arguments: &[u8],
    gas: u64,
) -> Result<(Vec<u8>, u64), Failure> {
    let mut machine = Machine::acquire(&program.0).map_err(|unavailable| match unavailable {
        Unavailable::Full => Failure::Depth,
        Unavailable::Missing => Failure::Unknown,
    })?;
    if !machine.map_read_only(ARGUMENTS, arguments.len() as u64, arguments) {
        return Err(Failure::Trapped);
    }
    machine.set_gas(gas);
    machine.set_register(7, ARGUMENTS);
    machine.set_register(8, arguments.len() as u64);
    loop {
        match machine.invoke() {
            Exit::Host(id) if precompile::price(id).is_some() => {
                serve_precompile(meter, &mut machine, id)?;
            }
            Exit::Halt => {
                let used = gas - machine.gas();
                let len = machine.register(8) as usize;
                if len > cap::REPLY {
                    return Err(Failure::Cap);
                }
                let output = machine.peek(machine.register(7), len).ok_or(Failure::Cap)?;
                return Ok((output, used));
            }
            Exit::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

/// The agent-relative key of the row an operation names: its rows, by the
/// register `rows`, and the actor's key at `address`.
fn row(
    machine: &mut Machine,
    instance: InstanceId,
    rows: u64,
    address: u64,
    len: u64,
) -> Result<Vec<u8>, Failure> {
    let key = read_key(machine, address, len)?;
    let rows = Rows::from_register(rows).ok_or(Failure::Trapped)?;
    keys::row(instance, rows, &key)
}

/// A row operation's key: its bytes, and the price of transforming them.
fn read_key(machine: &mut Machine, address: u64, len: u64) -> Result<Vec<u8>, Failure> {
    let key = read(machine, address, len, cap::KEY)?;
    if !machine.charge(key.len() as u64 * price::KEY_BYTE) {
        return Err(Failure::OutOfGas);
    }
    Ok(key)
}

/// The actor's bytes, at most `limit`: a longer buffer exceeds a cap and
/// an unreadable one traps.
fn read(machine: &mut Machine, address: u64, len: u64, limit: usize) -> Result<Vec<u8>, Failure> {
    let len = usize::try_from(len).map_err(|_| Failure::Cap)?;
    if len > limit {
        return Err(Failure::Cap);
    }
    if !machine.charge(len as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.peek(address, len).ok_or(Failure::Trapped)
}

/// Write `bytes` into the actor's memory through the machine's tracked
/// write, at their price.
fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), Failure> {
    if !machine.charge(bytes.len() as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.write(address, bytes)
}

fn copy_out(
    machine: &mut Machine,
    bytes: &[u8],
    address: u64,
    offset: u64,
    capacity: u64,
) -> Result<(), Failure> {
    let offset = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let len = usize::try_from(capacity)
        .unwrap_or(usize::MAX)
        .min(bytes.len() - offset);
    write(machine, address, &bytes[offset..offset + len])
}
