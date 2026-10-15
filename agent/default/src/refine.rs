//! Refine: a batch's inputs as steps, each an actor invocation served
//! against overlays of this refine's writes, or a workflow's step; or a
//! query on applied state. On JAM, a batch comes as a package with the
//! witness of the state it touches ([`jam`]).

mod invocation;
mod jam;
mod sessions;
mod snapshots;
mod workflows;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ops::Range;

use vos_wire::abi::{Failure, Kind, Refusal, cap, code};
use vos_wire::batch::{Admin, Await, Batch, Body, Input, Message, Query, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, WorkflowId};
use vos_wire::jam::RefineArgs;
use vos_wire::keys::Due;
use vos_wire::records::{Derivation, Installed, SessionMark, Workflow, unstored, unversioned};
use vos_wire::result::{
    CommittedWrite, InputRef, Outcome, Outgoing, PAGE, PageSection, ResultWriter, Run, Step, Write,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, keys};

use crate::host::{STATE_SCAN, ecalli, gas, ptr, state_read, state_read_into, unserved};
use crate::machines::Machine;
use invocation::Invocation;
use jam::Witnessed;
use sessions::{ByName, Counts, Held, admit, by_name};
use snapshots::Format;
use workflows::Floor;

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
        Work::Batch(batch) => {
            let mut base = Base::new(agent, &batch, Source::Node);
            let result = run_batch(&mut base, batch);
            result.finish(base.section.into_inner())
        }
        Work::Query(query) => run_query(agent, query).encode(),
        Work::Package(package) => jam::run(agent, package),
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

/// Where a refine reads applied state.
enum Source {
    /// The node, through `state_read` and `state_scan`.
    Node,
    /// A JAM package's witness, verified against its root.
    Witness(Witnessed),
}

/// A page of rows under `prefix` after `after` from the node, their values
/// as stored.
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
    source: Source,
    time: u64,
    seed: [u8; 32],
    /// The batch's whole budget, which the meter takes from.
    budget: u64,
    meter: Meter,
    /// Writes of the steps already committed in this refine, in order.
    earlier: Overlay,
    /// Installed records read in this refine. Only admin steps change
    /// them, and they clear it.
    installed: RefCell<BTreeMap<InstanceId, Option<Rc<Installed>>>>,
    /// The output's page section, and where in it lies each page the
    /// steps taken stored, or that they dropped: a later step of the
    /// workflow restores from there.
    section: RefCell<PageSection>,
    pages: BTreeMap<(WorkflowId, u32), Option<Range<usize>>>,
}

impl Base {
    fn new(agent: AgentId, batch: &Batch, source: Source) -> Self {
        Self {
            agent,
            source,
            time: batch.time,
            seed: batch.seed,
            budget: batch.budget,
            meter: Meter::new(batch.budget),
            earlier: BTreeMap::new(),
            installed: RefCell::new(BTreeMap::new()),
            section: RefCell::new(PageSection::new()),
            pages: BTreeMap::new(),
        }
    }

    /// How this refine's page section, and the node's page rows, hold a
    /// page: whole on JAM, which exports them as they are.
    fn format(&self) -> Format {
        match self.source {
            Source::Node => Format::Compressed,
            Source::Witness(_) => Format::Whole,
        }
    }

    /// A row of applied state as stored, by agent-relative key; `None`
    /// when absent.
    fn stored(&self, key: &[u8]) -> Option<Vec<u8>> {
        match &self.source {
            Source::Node => state_read(key),
            Source::Witness(witnessed) => witnessed.read(key).map(<[u8]>::to_vec),
        }
    }

    /// The length of a row of applied state as stored, without reading it.
    fn stored_len(&self, key: &[u8]) -> Option<usize> {
        match &self.source {
            Source::Node => state_read_into(key, &mut []),
            Source::Witness(witnessed) => witnessed.read(key).map(<[u8]>::len),
        }
    }

    /// A value of applied state, by agent-relative key.
    fn applied(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        self.stored(key)
            .map(|bytes| stored_value(key, &bytes).map(<[u8]>::to_vec))
            .transpose()
    }

    /// An agent record of applied state. A small one, as marks and ids
    /// are, is read and decoded on the stack.
    fn record<T: Decode>(&self, key: &[u8]) -> Result<Option<T>, Corrupt> {
        let decode = |bytes: &[u8]| {
            let value = unstored(bytes).ok_or(Corrupt)?;
            T::decode(value)
                .map(|(value, _)| Some(value))
                .map_err(|_| Corrupt)
        };
        if let Source::Witness(witnessed) = &self.source {
            return witnessed.read(key).map_or(Ok(None), decode);
        }
        // Every record refine reads fits, the stored byte included (a
        // session mark takes 17 bytes); a larger one is read again whole.
        let mut small = [0u8; 32];
        match state_read_into(key, &mut small) {
            None => Ok(None),
            Some(len) if len <= small.len() => decode(&small[..len]),
            Some(_) => state_read(key).map_or(Ok(None), |bytes| decode(&bytes)),
        }
    }

    /// Applied rows under `prefix` after `after`, a page at a time.
    fn applied_rows(&self, prefix: &[u8], after: &[u8]) -> Result<StateRows, Corrupt> {
        self.scan_page(prefix, after)
            .into_iter()
            .map(|(key, value)| {
                let value = stored_value(&key, &value)?.to_vec();
                Ok((key, value))
            })
            .collect()
    }

    /// A page of rows under `prefix` after `after`, their values as
    /// stored: at most [`SCAN_PAGE`] bytes of them, or room for the first
    /// alone.
    fn scan_page(&self, prefix: &[u8], after: &[u8]) -> StateRows {
        if let Source::Witness(witnessed) = &self.source {
            return witnessed
                .scan(prefix, after, SCAN_PAGE)
                .or_else(|| witnessed.scan(prefix, after, cap::STORED_ROW))
                .expect("a stored row past its cap");
        }
        scan_page(prefix, after)
    }

    /// A value through this refine's earlier steps and applied state.
    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        match self.earlier.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.applied(key),
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
            None => self.stored_len(&key).unwrap_or(0),
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

    /// Workflow `id`'s page `index`, whose snapshot names it by `hash`,
    /// read into `page`: from the section when a step of this refine
    /// stored it, else from its row, which on JAM holds the page's hash,
    /// `hash` itself, and the package an import of the page. False when a
    /// step dropped it, no row holds it, or what holds it is not a page.
    fn page(
        &self,
        id: WorkflowId,
        index: u32,
        hash: &[u8; 32],
        page: &mut [u8; PAGE],
    ) -> Result<bool, Corrupt> {
        let format = self.format();
        match self.pages.get(&(id, index)) {
            Some(Some(range)) => Ok(format.unpack(self.section.borrow().page(range.clone()), page)),
            Some(None) => Ok(false),
            None => Ok(
                match (self.applied(&keys::page(id, index))?, &self.source) {
                    (None, _) => false,
                    (Some(row), Source::Node) => format.unpack(&row, page),
                    (Some(row), Source::Witness(witnessed)) => {
                        row == hash && witnessed.import(id, index, page)
                    }
                },
            ),
        }
    }

    /// Whether a row is there, through this refine's earlier steps,
    /// whatever its value.
    fn holds(&self, key: &[u8]) -> bool {
        match self.earlier.get(key) {
            Some(value) => value.is_some(),
            None => self.stored_len(key).is_some(),
        }
    }

    /// A principal's role byte, through this refine's earlier steps.
    fn role(&self, principal: &Principal) -> Result<Option<u8>, Corrupt> {
        Ok(self
            .read(&keys::member(principal))?
            .and_then(|bytes| bytes.first().copied()))
    }
}

/// A mark a step advances once it is in the result.
enum Mark {
    Session(Session, Held),
    Pair(AgentId, u64),
}

/// A step as the batch takes it: what the result records, the mark it
/// advances, where in the section lie the pages it stores, and the
/// workflows due after it, a start's or a sweep's, each with the time its
/// row in the due index lies at.
struct Stepped {
    step: Step,
    mark: Option<Mark>,
    pages: Vec<Range<usize>>,
    due: Vec<(u64, WorkflowId)>,
}

impl Stepped {
    fn new(step: Step, mark: Option<Mark>) -> Self {
        Self {
            step,
            mark,
            pages: Vec::new(),
            due: Vec::new(),
        }
    }
}

/// What a batch has taken so far: the marks, sessions and counts its
/// steps moved, and the result.
struct Batched {
    sessions: BTreeMap<ByName, Held>,
    pairs: BTreeMap<AgentId, u64>,
    counts: Counts,
    /// Whether a step in the result ran a handler or a workflow.
    handled: bool,
    result: ResultWriter,
}

impl Batched {
    /// Take `stepped` into the result, which `reserve` was kept for: the
    /// workflows due after it; `None`, with nothing taken, when it overran
    /// the budget behind a step that ran a handler, or the result cannot
    /// hold it.
    ///
    /// A step that overran the budget, reading records, serving precompiles
    /// or writing a workflow's pages, waits for the next batch behind a step
    /// that ran a handler. With none before it, only inputs that run none
    /// came first, a sweep or acknowledgements, which leave it as little
    /// room in any batch: it fails, consumed. A step the result or its page
    /// section cannot hold waits too; one alone always fits
    /// (`cap::STEP_RESULT`, a workflow's `cap::WORKFLOW_STEP_RESULT`).
    fn take(
        &mut self,
        base: &mut Base,
        stepped: Stepped,
        reserve: u64,
        handler: bool,
    ) -> Option<Vec<(u64, WorkflowId)>> {
        let overrun = base.meter.overrun.replace(false);
        let section = base.section.get_mut();
        if (overrun && self.handled) || !section.fits() || !self.result.push(&stepped.step) {
            section.drop_running();
            return None;
        }
        section.take();
        let Step::Ran(run) = &stepped.step else {
            base.meter.left.set(base.meter.left.get() - reserve);
            return Some(stepped.due);
        };
        self.handled |= handler;
        base.meter
            .left
            .set(base.meter.left.get() - reserve - run.gas_used);
        for write in &run.writes {
            base.earlier.insert(write.key.clone(), write.value.clone());
        }
        for write in &run.committed {
            let key = keys::committed(&write.map, &write.key);
            base.earlier.insert(key, write.value.clone());
        }
        let mut stored = stepped.pages.into_iter();
        for page in &run.pages {
            let range = page
                .hash
                .map(|_| stored.next().expect("a stored page's place"));
            base.pages.insert((page.workflow, page.index), range);
        }
        match stepped.mark {
            Some(Mark::Session(session, held)) => {
                self.sessions.insert(by_name(&session), held);
            }
            Some(Mark::Pair(from, sequence)) => {
                self.pairs.insert(from, sequence);
            }
            None => {}
        }
        Some(stepped.due)
    }
}

/// What dispatching an input keeps of the meter while it runs: its
/// reserve, its handler's limit, and for a reply, the workflow it resumes
/// with what the meter keeps for its step; and whether its step runs a
/// handler or a workflow.
struct Plan {
    reserve: u64,
    limit: u64,
    resumes: Option<(Workflow, Option<(u64, u64)>)>,
    runs: bool,
}

/// An input's plan, its installed record or workflow read and paid above
/// its reserve; `None` when the meter cannot keep its reserve or pay what
/// it reads. A reply is checked against its pair's order before the
/// workflow it may resume is read.
fn plan(base: &Base, pairs: &BTreeMap<AgentId, u64>, input: &Input, handler: bool) -> Option<Plan> {
    let reserve = match input {
        _ if handler => defaults::STEP_RESERVE,
        Input::Admin(_) => defaults::INSTALL_RESERVE,
        Input::Sweep { .. } => defaults::SWEEP_RESERVE,
        _ => defaults::INPUT_RESERVE,
    };
    base.meter.kept.set(reserve + defaults::FINISH_RESERVE);
    if base.meter.left.get() < base.meter.kept.get() {
        return None;
    }
    let plain = |limit| {
        Some(Plan {
            reserve,
            limit,
            resumes: None,
            runs: handler,
        })
    };
    match input {
        Input::Request(request) => plain(limit(base, request.instance, request.method)?),
        Input::Message(Message {
            body: Body::Call {
                instance, method, ..
            },
            ..
        }) => plain(limit(base, *instance, *method)?),
        Input::Message(Message {
            from,
            sequence,
            body: Body::Reply { awaiting, .. },
        }) if out_of_order(base, pairs, *from, *sequence).is_none() => {
            match workflows::resumed(base, *from, awaiting) {
                Err(_) => None,
                Ok(Some((workflow, bytes))) => {
                    // One that could never run fails at once, running none.
                    let kept = workflows::kept(base, &workflow, bytes);
                    let (reserve, limit) = kept.unwrap_or((reserve, 0));
                    Some(Plan {
                        reserve,
                        limit,
                        resumes: Some((workflow, kept)),
                        runs: kept.is_some(),
                    })
                }
                Ok(None) => plain(0),
            }
        }
        _ => plain(0),
    }
}

/// Run a batch's inputs as steps, within its budget, each followed by the
/// steps of the workflows it makes due at once, as far as the budget goes:
/// the work result, its pages left in `base`'s section.
fn run_batch(base: &mut Base, batch: Batch) -> ResultWriter {
    // The one reading of `gas`. A node gives a refine its batch's budget and
    // what decoding the batch may take (`defaults::refine_start`), so the
    // budget is left now; a refine given less traps rather than run out
    // partway, and nothing else depends on the reading.
    assert!(
        gas() >= batch.budget,
        "the refine's gas does not cover its budget"
    );
    // A sweep's due steps leave the batch's other inputs their floor.
    let with_inputs = batch
        .inputs
        .iter()
        .any(|input| !matches!(input, Input::Sweep { .. }));
    let mut batched = Batched {
        sessions: BTreeMap::new(),
        pairs: BTreeMap::new(),
        counts: Counts::default(),
        handled: false,
        result: ResultWriter::new(batch.version, batch.time, batch.seed),
    };
    for input in batch.inputs {
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
        let Some(plan) = plan(base, &batched.pairs, &input, handler) else {
            break;
        };
        let kept = plan.reserve + plan.limit + defaults::FINISH_RESERVE;
        if base.meter.left.get() < kept {
            break;
        }
        base.meter.kept.set(kept);
        let index = batched.result.count();
        let admin = matches!(input, Input::Admin(_));
        let swept = matches!(input, Input::Sweep { .. });
        // The key of a session this step creates.
        let mut creates = None;
        let stepped = match input {
            Input::Request(request) => {
                match admit(base, &batched.sessions, &mut batched.counts, &request) {
                    (input, Err(code)) => Stepped::new(Step::Refused { input, code }, None),
                    (input, Ok(held)) => {
                        if let Held::Absent = held {
                            creates = Some(request.session.key);
                        }
                        let mark = SessionMark {
                            sequence: request.sequence,
                            time: base.time,
                        };
                        let mark = Mark::Session(request.session, held.advanced(mark));
                        let mut stepped = called(
                            base,
                            index,
                            input,
                            request.caller,
                            request.instance,
                            request.method,
                            &request.arguments,
                        );
                        stepped.mark = Some(mark);
                        stepped
                    }
                }
            }
            Input::Message(message) => {
                self::message(base, &batched.pairs, index, message, plan.resumes)
            }
            Input::Failed {
                from,
                sequence,
                awaiting,
            } => failed_in_refine(base, &batched.pairs, from, sequence, awaiting),
            Input::Admin(admin) => Stepped::new(self::admin(admin), None),
            Input::Ack { to, sequence } => Stepped::new(acknowledge(to, sequence), None),
            Input::Sweep { due } => sweep(base, &due),
        };
        let Some(due) = batched.take(base, stepped, plan.reserve, plan.runs) else {
            break;
        };
        if let Some(key) = creates {
            batched.counts.add(&key);
        }
        if admin {
            // An admin step may change installed records.
            base.installed.borrow_mut().clear();
        }
        let mut floor = Floor::new(swept && with_inputs);
        for (at, workflow) in due {
            if !workflows::due(base, &mut batched, at, workflow, &mut floor) {
                break;
            }
        }
    }
    batched.result
}

/// A request's or a call's step: a handler's command, or a workflow's
/// start, which its first step follows when the budget allows.
fn called(
    base: &Base,
    index: u32,
    input: InputRef,
    caller: Principal,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Stepped {
    if workflows::is_start(base, instance, method) {
        let (run, started) = workflows::start(base, input, caller, instance, method, arguments);
        let mut stepped = Stepped::new(Step::Ran(run), None);
        stepped
            .due
            .extend(started.map(|workflow| (base.time, workflow)));
        return stepped;
    }
    let run = command(base, index, input, caller, instance, method, arguments);
    Stepped::new(Step::Ran(run), None)
}

/// The gas limit a handler's schema requests, capped; 0 for an input that
/// will fail before running, or that starts a workflow, whose steps
/// follow. `None` when the meter cannot pay the installed record that
/// gives it.
fn limit(base: &Base, instance: InstanceId, method: MethodId) -> Option<u64> {
    let installed = match base.installed(instance) {
        Err(Failure::OutOfGas) => return None,
        installed => installed.ok().flatten(),
    };
    Some(
        installed
            .and_then(|installed| {
                let schema = installed.schema.method(method)?;
                schema.kind.is_handler().then(|| schema.gas_limit())
            })
            .unwrap_or(0),
    )
}

/// Why a message from `from` at `sequence` is out of its pair's order, if
/// it is.
fn out_of_order(
    base: &Base,
    pairs: &BTreeMap<AgentId, u64>,
    from: AgentId,
    sequence: u64,
) -> Option<Refusal> {
    let mark = match pairs.get(&from) {
        Some(mark) => Ok(Some(*mark)),
        None => base.record::<u64>(&keys::pair_in(from)),
    };
    match mark {
        Err(Corrupt) => Some(Refusal::Unreadable),
        Ok(mark) if sequence != mark.unwrap_or(0) + 1 => Some(Refusal::Sequence),
        Ok(_) => None,
    }
}

/// A message in its pair's order: a call runs as a command of the
/// sending agent's, or starts a workflow; a reply resumes the workflow
/// that awaits it, `resumes`, or is consumed and dropped; a wait for a
/// workflow's result is answered, or held until it ends. A request gets
/// its reply among the step's messages, whatever its outcome.
fn message(
    base: &Base,
    pairs: &BTreeMap<AgentId, u64>,
    index: u32,
    message: Message,
    resumes: Option<(Workflow, Option<(u64, u64)>)>,
) -> Stepped {
    let (from, sequence) = (message.from, message.sequence);
    let input = InputRef::Message { from, sequence };
    if let Some(code) = out_of_order(base, pairs, from, sequence) {
        return Stepped::new(Step::Refused { input, code }, None);
    }
    let mut stepped = match message.body {
        Body::Call {
            instance,
            method,
            arguments,
            awaiting,
        } => {
            let caller = Principal::Agent(from);
            let mut stepped = called(base, index, input, caller, instance, method, &arguments);
            if let Step::Ran(run) = &mut stepped.step {
                answer(run, from, awaiting);
            }
            stepped
        }
        Body::Reply { awaiting, answer } => match resumes {
            Some((workflow, kept)) => {
                let id = awaiting.workflow;
                let resume = answer.encode();
                workflows::resume_step(base, index, input, id, workflow, resume, kept, 0)
            }
            None => Stepped::new(Step::Ran(consumed(input, Outcome::Done(Vec::new()))), None),
        },
        Body::Wait { workflow, awaiting } => {
            let run = workflows::wait(base, input, from, workflow, awaiting);
            Stepped::new(Step::Ran(run), None)
        }
    };
    stepped.mark = Some(Mark::Pair(from, sequence));
    stepped
}

/// A message the leader asserts failed in refine, in its pair's order:
/// consumed as failed without running, and answered when it awaits.
fn failed_in_refine(
    base: &Base,
    pairs: &BTreeMap<AgentId, u64>,
    from: AgentId,
    sequence: u64,
    awaiting: Option<Await>,
) -> Stepped {
    let input = InputRef::Message { from, sequence };
    if let Some(code) = out_of_order(base, pairs, from, sequence) {
        return Stepped::new(Step::Refused { input, code }, None);
    }
    let mut run = consumed(input, Outcome::failed(Failure::InRefine));
    answer(&mut run, from, awaiting);
    Stepped::new(Step::Ran(run), Some(Mark::Pair(from, sequence)))
}

/// Add the reply to agent `to`'s request awaiting at `awaiting`, if any,
/// after `run`'s own messages: the step's outcome.
fn answer(run: &mut Run, to: AgentId, awaiting: Option<Await>) {
    if let Some(awaiting) = awaiting {
        let answer = run.outcome.clone().into();
        run.messages.push(Outgoing::reply(to, awaiting, answer));
    }
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
        pages: Vec::new(),
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
    let Outcome::Done(_) = outcome else {
        let mut run = consumed(input, outcome);
        run.instances = instances;
        run.gas_used = gas_used;
        return run;
    };
    let (writes, committed) = split_writes(frames.pop().expect("the step overlay"));
    Run {
        input,
        outcome,
        instances,
        writes,
        committed,
        messages,
        attests,
        pages: Vec::new(),
        gas_used,
    }
}

/// A step's writes: those to committed maps apart, by map and transformed
/// key.
fn split_writes(overlay: Overlay) -> (Vec<Write>, Vec<CommittedWrite>) {
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
        source: Source::Node,
        time: query.time,
        seed: query.seed,
        // One invocation, within its handler's limit: nothing to dispatch.
        budget: u64::MAX,
        meter: Meter::new(u64::MAX),
        earlier: BTreeMap::new(),
        installed: RefCell::new(BTreeMap::new()),
        section: RefCell::new(PageSection::new()),
        pages: BTreeMap::new(),
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

/// The rows of the due index the leader listed, each still there and due
/// at the batch's time: the sessions among them, each its row's time and
/// id, for accumulate to collect or file again, and the workflows, whose
/// steps follow. A row not there, or not due, is passed over.
fn sweep(base: &Base, listed: &[(u64, Due)]) -> Stepped {
    let mut sessions = Vec::new();
    let mut workflows = Vec::new();
    for &(at, entry) in listed.iter().take(defaults::SWEEP_LIMIT) {
        if at > base.time || !base.holds(&keys::due(at, entry)) {
            continue;
        }
        match entry {
            Due::Session(session) => sessions.push((at, session)),
            Due::Workflow(workflow) => workflows.push((at, workflow)),
        }
    }
    let mut stepped = Stepped::new(Step::Swept { due: sessions }, None);
    stepped.due = workflows;
    stepped
}

/// An operator command: install a package or set a role. Its writes are
/// under the step write cap like any step's.
fn admin(admin: Admin) -> Step {
    let failed = |code| Step::Ran(consumed(InputRef::Admin, Outcome::failed(code)));
    let (write, reply) = match admin {
        Admin::Install {
            instance,
            derivation,
            roles,
        } => {
            let reply = derivation.encode();
            let Some(installed) = install(derivation, roles) else {
                return failed(Failure::Unknown);
            };
            let write = Write {
                key: keys::installed(instance),
                value: Some(installed.encode()),
            };
            (write, reply)
        }
        Admin::SetRole(grant) => {
            let write = Write {
                key: keys::member(&grant.principal),
                value: grant.role.map(|role| alloc::vec![role]),
            };
            (write, Vec::new())
        }
    };
    if write.key.len() + write.value.as_ref().map_or(0, Vec::len) > cap::STEP_WRITES {
        return failed(Failure::Cap);
    }
    let mut run = consumed(InputRef::Admin, Outcome::Done(reply));
    run.writes.push(write);
    Step::Ran(run)
}

/// Read the actor program's schema from its machine and check the package:
/// each kernel is bound to an attestable method, every attestable method
/// has exactly one, and every role name is mapped.
fn install(derivation: Derivation, roles: Vec<(Vec<u8>, u8)>) -> Option<Installed> {
    // The program an install names, which its operator may never have
    // given the node, is not yet pinned: its absence fails the install.
    let machine = Machine::acquire(&derivation.program.0).ok()?;
    let header = machine.peek(SCHEMA_AT, 8)?;
    let len = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if len > vos_wire::schema::MAX_LEN {
        return None;
    }
    let section = machine.peek(SCHEMA_AT, 8 + len)?;
    let schema = Schema::read(&section).ok()?;
    let installed = Installed {
        derivation,
        roles,
        schema,
    };
    for &(method, _) in &installed.derivation.kernels {
        let schema = installed.schema.method(method)?;
        if schema.kind != Kind::Attestable {
            return None;
        }
    }
    let mut attestables = 0;
    for method in &installed.schema.methods {
        if method.kind == Kind::Attestable {
            attestables += 1;
            installed.kernel(method.id)?;
        }
        if let Some(role) = &method.role
            && installed.role(role).is_none()
        {
            return None;
        }
    }
    // Each kernel is bound to such a method, and each such method has one:
    // as many as there are of them, no method has two.
    (installed.derivation.kernels.len() == attestables).then_some(installed)
}
