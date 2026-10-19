//! The model's workflows: started by a request or a call, run in their
//! instance's actor program, stepped by the input that resumes each, a unit
//! at a time, reaching their instance's state in sections, and snapshotted
//! between steps as the default agent snapshots them: the counter after the
//! pausing call, or where the step was preempted, the registers, each page
//! the step wrote that differs from its base, and the call it left
//! unserved.
//!
//! It shares nothing with the agent's capture and restore: the written
//! pages are the interpreter's dirty pages, and a page's base is read from
//! the parsed program. It keeps no meter: of the budget, it knows only a
//! step that could never run in a batch of it, and a batch a test marks as
//! unable to cover a first effect ([`Testkit::uncovered`]); a step ended
//! at a page the meter cannot pay it does not model.

use std::collections::BTreeMap;

use vos_pvm::ExitReason;
use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
use vos_pvm::spi::StandardLayout;
use vos_wire::abi::cap::{self, Limits};
use vos_wire::abi::{self, AttestError, Failure, Kind, Op, code, price};
use vos_wire::batch::{Answer, Await};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, RequestId, WorkflowId};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Snapshot, Workflow, WorkflowState};
use vos_wire::result::{Attested, InstanceGas, Outcome, Outgoing, PAGE, Page, Write, digest};
use vos_wire::{Decode, Encode, defaults};

use crate::invocation::{Call, Ended, Invocation};
use crate::memory::precompile;
use crate::{Step, Testkit, split_writes};

type Rows = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// What a workflow's step resumes with: its input, or the rows its read at
/// a cut is served (`None`: unserved), which its kernel runs on first.
enum Resume {
    Input(Vec<u8>),
    Served(Option<Vec<u8>>),
}

/// How a step left its workflow: paused and captured, or ended.
enum Left {
    Paused(WorkflowState, Captured),
    Ended(Outcome),
}

/// A paused step's pages and snapshot: the entries its run lists, the bytes
/// of those it stores, in order, and the machine's snapshot.
struct Captured {
    pages: Vec<Page>,
    stored: Vec<Vec<u8>>,
    snapshot: Snapshot,
}

impl Testkit {
    /// A workflow's record, as the agent keeps it.
    pub fn workflow(&self, id: WorkflowId) -> Option<Workflow> {
        let bytes = self.state.get(&keys::workflow(id))?;
        Some(Workflow::decode(bytes).expect("a workflow").0)
    }

    pub(crate) fn is_workflow(&self, instance: InstanceId, method: MethodId) -> bool {
        self.instances
            .get(&instance)
            .and_then(|installed| installed.schema.method(method))
            .is_some_and(|schema| schema.kind == Kind::Workflow)
    }

    fn count(&self, key: &[u8]) -> u64 {
        self.state
            .get(key)
            .map_or(0, |bytes| u64::decode(bytes).expect("a count").0)
    }

    fn set_count(rows: &mut Rows, key: Vec<u8>, count: u64) {
        rows.insert(key, (count > 0).then(|| count.encode()));
    }

    fn file_due(rows: &mut Rows, id: WorkflowId, at: u64) {
        rows.insert(keys::due(at, Due::Workflow(id)), Some(Vec::new()));
    }

    fn unfile_due(rows: &mut Rows, id: WorkflowId, at: u64) {
        rows.insert(keys::due(at, Due::Workflow(id)), None);
    }

    fn move_due(rows: &mut Rows, id: WorkflowId, workflow: &mut Workflow, at: u64) {
        if workflow.due != at {
            Self::unfile_due(rows, id, workflow.due);
            Self::file_due(rows, id, at);
            workflow.due = at;
        }
    }

    /// Whether a step of `workflow` could run in a batch of the budget,
    /// behind a sweep: its reserve, arming its pages and restoring those it
    /// holds, its limit and the finish, its record read, and room for a page
    /// past what a sweep leaves the batch's inputs.
    fn fits(&self, workflow: &Workflow) -> bool {
        let held = workflow
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.pages.len()) as u64;
        defaults::WORKFLOW_RESERVE
            + u64::from(workflow.writable) * defaults::ARM_PAGE
            + held * defaults::RESTORED_PAGE
            + workflow.gas
            + defaults::FINISH_RESERVE
            + defaults::SWEEP_RESERVE
            + defaults::RECORD_BYTE * (workflow.encode().len() as u64 + 1)
            + 2 * defaults::WRITTEN_PAGE
            <= self.budget
    }

    /// Start a workflow, `call`'s method for its caller, its owner:
    /// `Started` with its id, the workflow due at once; or failed, as a step
    /// that could not run.
    pub(crate) fn start(&mut self, call: Call) -> Step {
        self.steps += 1;
        let (outcome, rows) = match self.started(call) {
            Ok((id, rows)) => (Outcome::Started(id), rows),
            Err(code) => (Outcome::failed(code), Rows::new()),
        };
        let mut step = Step::consumed(outcome);
        step.writes = split_writes(rows).0;
        self.apply(&step, Vec::new());
        step
    }

    fn started(&self, call: Call) -> Result<(WorkflowId, Rows), Failure> {
        let Call {
            caller: owner,
            instance,
            method,
            arguments,
        } = call;
        if arguments.len() > cap::REQUEST {
            return Err(Failure::Cap);
        }
        let installed = self.instances.get(&instance).ok_or(Failure::Unknown)?;
        let schema = installed.schema.method(method).ok_or(Failure::Unknown)?;
        if let Some(role) = &schema.role
            && self.members.get(&owner) != Some(&installed.roles[role])
        {
            return Err(Failure::Forbidden);
        }
        if schema.kind != Kind::Workflow {
            return Err(Failure::Unknown);
        }
        let blob = &installed.program;
        let program = ProgramHash::of(blob);
        let parsed = vos_pvm::spi::parse_standard_program(blob).ok_or(Failure::Unloadable)?;
        let layout = parsed.layout(&[]).ok_or(Failure::Unloadable)?;
        let writable =
            (layout.rw.size + layout.stack.size) / PAGE as u64 + u64::from(installed.heap);
        if writable > installed.target.limits().workflow_pages as u64 {
            return Err(Failure::Cap);
        }
        let live = self.count(&keys::live_workflows());
        if live >= defaults::MAX_WORKFLOWS {
            return Err(Failure::Cap);
        }
        let id = WorkflowId(self.count(&keys::next_workflow()));
        let record = Workflow {
            format: Workflow::FORMAT,
            program,
            instance,
            method,
            owner,
            gas: schema.gas_limit(),
            writable: writable as u32,
            awaits: 0,
            due: self.time,
            waiter: None,
            state: WorkflowState::Ready(arguments.to_vec()),
            snapshot: None,
            target: installed.target,
            stored: self.time,
        };
        let mut rows = Rows::new();
        Self::set_count(&mut rows, keys::next_workflow(), id.0 + 1);
        Self::set_count(&mut rows, keys::live_workflows(), live + 1);
        let pins = keys::workflow_pins(&program);
        Self::set_count(&mut rows, pins.clone(), self.count(&pins) + 1);
        Self::file_due(&mut rows, id, record.due);
        rows.insert(keys::workflow(id), Some(record.encode()));
        Ok((id, rows))
    }

    /// The step a row of the due index at `at` makes for workflow `id`:
    /// its first, its deadline's or timer's, its continuation once
    /// preempted, or its collection once ended; the row deleted when the
    /// workflow is gone or its record lies elsewhere.
    pub fn due(&mut self, at: u64, id: WorkflowId) -> Step {
        let Some(workflow) = self.workflow(id).filter(|workflow| workflow.due == at) else {
            return self.orphan(at, id);
        };
        let resume = match &workflow.state {
            WorkflowState::Ended(_) => {
                let mut rows = Rows::new();
                Self::unfile_due(&mut rows, id, workflow.due);
                rows.insert(keys::workflow(id), None);
                return self.quick(rows);
            }
            WorkflowState::Ready(input) | WorkflowState::Preempted(input) => input.clone(),
            WorkflowState::Awaiting { .. } => Answer::failed(Failure::TimedOut).encode(),
            WorkflowState::Sleeping { .. } => Vec::new(),
            WorkflowState::Attesting { .. } => Attested::Failed(AttestError::NotClosed).encode(),
        };
        self.step(id, workflow, Resume::Input(resume))
    }

    /// The step a read at window `window`'s cut, `request`, served
    /// (`None`: unserved) makes: the step of the workflow awaiting it,
    /// before its deadline, or one that runs nothing.
    pub fn resume_read(
        &mut self,
        window: u64,
        request: RequestId,
        served: Option<Vec<u8>>,
    ) -> Step {
        let workflow = self.workflow(request.workflow).filter(|workflow| {
            matches!(workflow.state, WorkflowState::Attesting { counter, window: at, deadline, .. }
                if counter == request.awaits && at == window && self.time < deadline)
        });
        match workflow {
            Some(workflow) => self.step(request.workflow, workflow, Resume::Served(served)),
            None => self.quick(Rows::new()),
        }
    }

    /// The step a row of the due index makes at `at` when it names a
    /// workflow that is gone, or whose record lies elsewhere: the row
    /// deleted.
    fn orphan(&mut self, at: u64, id: WorkflowId) -> Step {
        let mut rows = Rows::new();
        Self::unfile_due(&mut rows, id, at);
        self.quick(rows)
    }

    /// A step that runs nothing and writes `rows`.
    fn quick(&mut self, rows: Rows) -> Step {
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        step.writes = split_writes(rows).0;
        self.apply(&step, Vec::new());
        step
    }

    /// The step a reply from `from` makes when a workflow awaits it, at the
    /// await it names; `None` when none does.
    pub(crate) fn resume(
        &mut self,
        from: AgentId,
        awaiting: &Await,
        answer: &Answer,
    ) -> Option<Step> {
        let workflow = self.workflow(awaiting.workflow).filter(|workflow| {
            matches!(workflow.state, WorkflowState::Awaiting { agent, counter, deadline }
                if agent == from && counter == awaiting.counter && self.time < deadline)
        })?;
        Some(self.step(awaiting.workflow, workflow, Resume::Input(answer.encode())))
    }

    /// A wait from `from` for workflow `id`'s result: answered now if it
    /// ended, held for its end otherwise; `Unknown` unless `from` owns it.
    pub(crate) fn wait(&mut self, from: AgentId, id: WorkflowId, awaiting: Await) -> Step {
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        let answer = match self.workflow(id) {
            Some(mut workflow) if workflow.owner == Principal::Agent(from) => {
                match &workflow.state {
                    WorkflowState::Ended(outcome) => Some(outcome.clone().into()),
                    _ => {
                        workflow.waiter = Some(awaiting);
                        step.writes.push(Write {
                            key: keys::workflow(id),
                            value: Some(workflow.encode()),
                        });
                        None
                    }
                }
            }
            _ => Some(Answer::failed(Failure::Unknown)),
        };
        if let Some(answer) = answer {
            step.messages.push(Outgoing::reply(from, awaiting, answer));
        }
        self.apply(&step, Vec::new());
        step
    }

    /// A step of workflow `id` with `resume`, its read at a cut's kernel run
    /// first when served; one that could never run in a batch of the budget
    /// fails at once, past a cap. The request of a read it awaited goes.
    fn step(&mut self, id: WorkflowId, mut workflow: Workflow, resume: Resume) -> Step {
        let index = self.steps;
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        let mut rows = Rows::new();
        if let WorkflowState::Attesting {
            counter, window, ..
        } = workflow.state
        {
            let request = RequestId {
                workflow: id,
                awaits: counter,
            };
            rows.insert(keys::request(window, request), None);
        }
        if !self.fits(&workflow) {
            let outcome = Outcome::failed(Failure::Cap);
            step.outcome = outcome.clone();
            step.pages = self.end(id, &mut workflow, outcome, &mut rows, &mut step);
            step.writes = split_writes(rows).0;
            self.apply(&step, Vec::new());
            return step;
        }
        let mut invocation = Invocation::new(self, index, Kind::Workflow);
        invocation.limits = workflow.target.limits();
        invocation.awaits = Some(Await {
            workflow: id,
            counter: workflow.awaits,
        });
        let (resume, spent) = match (resume, &workflow.state) {
            (
                Resume::Served(served),
                WorkflowState::Attesting {
                    counter,
                    window,
                    method,
                    arguments,
                    ..
                },
            ) => {
                let request = RequestId {
                    workflow: id,
                    awaits: *counter,
                };
                let call = (*window, *method, arguments.as_slice());
                let (answer, spent) =
                    invocation.at_cut(workflow.instance, request, call, served, workflow.gas);
                (answer.encode(), spent)
            }
            (Resume::Served(_), _) => unreachable!("served a workflow that reads at no cut"),
            (Resume::Input(input), _) => (input, 0),
        };
        let left = self.run_step(&mut invocation, id, &workflow, &resume, spent);
        step.instances = invocation.instances.clone();
        step.gas_used = invocation.gas_used;
        let mut stored = Vec::new();
        // The step's effects, kept when it paused or ended with its result.
        let mut keep_effects = |rows: &mut Rows, step: &mut Step| {
            rows.extend(invocation.frames.pop().expect("the step overlay"));
            step.messages = std::mem::take(&mut invocation.messages);
            step.attests = std::mem::take(&mut invocation.attests);
        };
        match left {
            Ok(Left::Paused(state, captured)) => {
                keep_effects(&mut rows, &mut step);
                let at = match state {
                    WorkflowState::Awaiting { deadline, .. }
                    | WorkflowState::Attesting { deadline, .. } => deadline,
                    WorkflowState::Sleeping { until } => until,
                    // Due in the next millisecond, so its row moves.
                    WorkflowState::Preempted(_) => self.time + 1,
                    _ => unreachable!("a step pauses awaiting, asleep or preempted"),
                };
                if let WorkflowState::Awaiting { .. } | WorkflowState::Attesting { .. } = state {
                    workflow.awaits += 1;
                }
                Self::move_due(&mut rows, id, &mut workflow, at);
                workflow.state = state;
                // Every page it holds stored now: none is older.
                let restored = |index: &u32| {
                    captured
                        .pages
                        .iter()
                        .any(|page| page.index == *index && page.hash.is_some())
                };
                if captured
                    .snapshot
                    .pages
                    .iter()
                    .all(|(index, _)| restored(index))
                {
                    workflow.stored = self.time;
                }
                workflow.snapshot = Some(captured.snapshot);
                rows.insert(keys::workflow(id), Some(workflow.encode()));
                step.pages = captured.pages;
                stored = captured.stored;
            }
            Ok(Left::Ended(outcome)) => {
                if let Outcome::Done(_) = outcome {
                    keep_effects(&mut rows, &mut step);
                } else {
                    step.outcome = outcome.clone();
                }
                step.pages = self.end(id, &mut workflow, outcome, &mut rows, &mut step);
            }
            Err(code) => {
                let outcome = Outcome::failed(code);
                step.outcome = outcome.clone();
                step.pages = self.end(id, &mut workflow, outcome, &mut rows, &mut step);
            }
        }
        (step.writes, step.committed) = split_writes(rows);
        self.apply(&step, stored);
        step
    }

    /// End `workflow` with `outcome`: its pages dropped, its pin and its
    /// place among the live workflows released, its collection due after
    /// the result's keeping, and its owner told when it waits.
    fn end(
        &self,
        id: WorkflowId,
        workflow: &mut Workflow,
        outcome: Outcome,
        rows: &mut Rows,
        step: &mut Step,
    ) -> Vec<Page> {
        let pages = workflow
            .snapshot
            .take()
            .map(|snapshot| snapshot.pages)
            .unwrap_or_default()
            .into_iter()
            .map(|(index, _)| Page {
                workflow: id,
                index,
                hash: None,
            })
            .collect();
        let pins = keys::workflow_pins(&workflow.program);
        Self::set_count(rows, pins.clone(), self.count(&pins).saturating_sub(1));
        let live = self.count(&keys::live_workflows());
        Self::set_count(rows, keys::live_workflows(), live.saturating_sub(1));
        let collected = self.time.saturating_add(defaults::WORKFLOW_KEPT_MS);
        Self::move_due(rows, id, workflow, collected);
        if let (Some(awaiting), Principal::Agent(owner)) = (workflow.waiter.take(), workflow.owner)
        {
            step.messages
                .push(Outgoing::reply(owner, awaiting, outcome.clone().into()));
        }
        workflow.state = WorkflowState::Ended(outcome);
        rows.insert(keys::workflow(id), Some(workflow.encode()));
        pages
    }

    /// Restore workflow `id`'s machine, run it through the step with
    /// `resume` as its input, `spent` of its limit already spent on its read
    /// at a cut, and capture it if it paused.
    fn run_step(
        &self,
        invocation: &mut Invocation,
        id: WorkflowId,
        workflow: &Workflow,
        resume: &[u8],
        spent: u64,
    ) -> Result<Left, Failure> {
        // Its target keeps its pages for a time: past it, it ends.
        let holds = workflow
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.pages.is_empty());
        if let Some(kept) = workflow.target.limits().pages_kept
            && holds
            && self.time >= workflow.stored + kept
        {
            return Err(Failure::Expired);
        }
        let blob = self
            .programs
            .get(&workflow.program)
            .ok_or(Failure::Unloadable)?;
        let parsed = vos_pvm::spi::parse_standard_program(blob).ok_or(Failure::Unloadable)?;
        let layout = parsed.layout(&[]).ok_or(Failure::Unloadable)?;
        let prepared = PreparedProgram::new(blob).map_err(|_| Failure::Unloadable)?;
        let counter = workflow
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.counter);
        let mut machine =
            Machine::load_prepared_at(&prepared, counter, &[], workflow.gas, MemoryModel::Auto)
                .map_err(|_| Failure::Trapped)?;
        // The rest of its heap, past its program's read-write data.
        let own = (layout.rw.size + layout.stack.size) / PAGE as u64;
        let heap = u64::from(workflow.writable) - own;
        let first = ((layout.rw.base + layout.rw.size) / PAGE as u64) as usize;
        assert!(machine.memory_mut().set_page_range(
            first,
            heap as usize,
            vos_pvm::interpreter::PERM_RW
        ));
        // The halt address and the stack's top, as a new machine's.
        let registers = machine.registers_mut();
        registers.fill(0);
        registers[..2].copy_from_slice(&layout.registers[..2]);
        if let Some(snapshot) = &workflow.snapshot {
            registers.copy_from_slice(&snapshot.registers);
            for (index, hash) in &snapshot.pages {
                let bytes = &self.pages[&(id, *index)];
                assert_eq!(digest(bytes), *hash, "a stored page's hash");
                assert!(
                    machine
                        .memory_mut()
                        .write_bytes_checked(index * PAGE as u32, bytes)
                );
            }
        }
        // Its first step enters the actor program as a handler does, the
        // method routed; a machine preempted resumes as it was; one paused
        // learns its input's length.
        let registers = machine.registers_mut();
        match (&workflow.snapshot, &workflow.state) {
            (None, _) => {
                registers[7] = u64::from(workflow.method.0);
                registers[8] = Kind::Workflow.index().into();
                registers[9] = resume.len() as u64;
            }
            (Some(_), WorkflowState::Preempted(_)) => {}
            (Some(_), _) => {
                registers[7] = resume.len() as u64;
                registers[8] = 0;
            }
        }
        machine.memory_mut().take_dirty_pages();
        let pending = workflow
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.pending);
        let call = Call {
            caller: workflow.owner,
            instance: workflow.instance,
            method: workflow.method,
            arguments: resume,
        };
        let resumed = *machine.registers();
        let ended = invocation.workflow(&mut machine, call, workflow.gas, pending, spent)?;
        // The pages the step wrote, among those the program may write, the
        // rest of its heap among them.
        let runs = [(layout.rw, heap), (layout.stack, 0)].map(|(region, more)| {
            region.base / PAGE as u64..(region.base + region.size) / PAGE as u64 + more
        });
        let written: Vec<u64> = machine
            .memory_mut()
            .take_dirty_pages()
            .into_iter()
            .flat_map(|range| u64::from(range.start)..u64::from(range.end))
            .filter(|page| runs.iter().any(|run| run.contains(page)))
            .collect();
        let (state, pending) = match ended {
            Ended::Paused(state) => (state, None),
            Ended::Preempted { pending, idle } => {
                // Out of gas with no call served and no page written since
                // it resumed, its registers and counter where they were: it
                // could not move. A page written is a move whatever the
                // registers say, as a loop that writes only memory may
                // start each block with the registers it resumed with.
                if idle
                    && written.is_empty()
                    && machine.registers()[..] == resumed[..]
                    && machine.interpreter().pc == counter
                {
                    return Err(Failure::OutOfGas);
                }
                (WorkflowState::Preempted(resume.to_vec()), pending)
            }
            Ended::Replied(result) => return Ok(Left::Ended(Outcome::Done(result))),
            Ended::Failed(detail) => {
                return Ok(Left::Ended(Outcome::Failed {
                    code: Failure::Handler,
                    detail,
                }));
            }
            Ended::Forbidden => unreachable!("a workflow is never refused"),
        };
        let held = workflow
            .snapshot
            .as_ref()
            .map_or(&[][..], |snapshot| &snapshot.pages);
        let limits = workflow.target.limits();
        let captured = capture(&machine, &layout, limits, id, held, written, pending)?;
        Ok(Left::Paused(state, captured))
    }
}

/// A paused step captured: each page it wrote, of `written`, stored by its
/// hash when it differs from its base, the read-write data where it lies
/// and zeros elsewhere, and from what the workflow `held`, or dropped when
/// back at its base; and the machine's snapshot, with the call it left
/// unserved, `pending`. Past `limits`' step pages written, or its held
/// pages held after, the step fails.
fn capture(
    machine: &Machine,
    layout: &StandardLayout,
    limits: &Limits,
    id: WorkflowId,
    held: &[(u32, [u8; 32])],
    written: Vec<u64>,
    pending: Option<u64>,
) -> Result<Captured, Failure> {
    if written.len() * PAGE > limits.step_pages {
        return Err(Failure::Cap);
    }
    let mut now: BTreeMap<u32, [u8; 32]> = held.iter().copied().collect();
    let mut pages = Vec::new();
    let mut stored = Vec::new();
    for page in written {
        let index = page as u32;
        let mut bytes = vec![0; PAGE];
        assert!(
            machine
                .memory()
                .read_bytes_checked(index * PAGE as u32, &mut bytes)
        );
        // The page's base: the read-write data where it lies, zeros
        // elsewhere.
        let mut base = vec![0; PAGE];
        let address = page * PAGE as u64;
        if address >= layout.rw.base {
            let start = (address - layout.rw.base) as usize;
            if start < layout.rw_data.len() {
                let end = (start + PAGE).min(layout.rw_data.len());
                base[..end - start].copy_from_slice(&layout.rw_data[start..end]);
            }
        }
        if bytes == base {
            if now.remove(&index).is_some() {
                pages.push(Page {
                    workflow: id,
                    index,
                    hash: None,
                });
            }
            continue;
        }
        let hash = digest(&bytes);
        if now.insert(index, hash) != Some(hash) {
            pages.push(Page {
                workflow: id,
                index,
                hash: Some(hash),
            });
            stored.push(bytes);
        }
    }
    if now.len() > limits.held_pages {
        return Err(Failure::Cap);
    }
    // Past the call it stopped at, or where it ran out of gas, or where
    // it was restored when it stopped before running.
    let interpreter = machine.interpreter();
    let counter = interpreter
        .pending_host_call()
        .map_or(interpreter.pc, |call| call.resume_pc);
    let snapshot = Snapshot {
        counter,
        registers: machine.registers().to_vec(),
        pages: now.into_iter().collect(),
        pending,
    };
    Ok(Captured {
        pages,
        stored,
        snapshot,
    })
}

/// What a workflow's step may spend: its limit, the effect-free code's
/// share in all and each effectful unit's own; the gas its machine has been
/// given; whether the running unit has made an effect; and whether the
/// machine has served a call since it resumed.
struct Share {
    limit: u64,
    allotted: u64,
    effectful: bool,
    served: bool,
}

impl Share {
    fn used(&self, machine: &Machine) -> u64 {
        self.allotted - machine.gas_remaining()
    }
}

/// Set a machine's gas.
fn set_gas(machine: &mut Machine, gas: u64) {
    machine.charge(machine.gas_remaining());
    machine.credit(gas);
}

/// The step's end between two awaits, before the call `pending` when
/// given: only effect-free, and once the machine has `moved` since it
/// resumed; else it fails, out of gas.
fn preempt_or_fail(
    share: &Share,
    moved: bool,
    pending: Option<u64>,
    idle: bool,
) -> Result<Ended, Failure> {
    if share.effectful || !moved {
        return Err(Failure::OutOfGas);
    }
    Ok(Ended::Preempted { pending, idle })
}

impl Invocation<'_> {
    /// Run a workflow's machine, `call` its method by its owner on the
    /// step's input, through its step a unit at a time, the host call
    /// `pending` first: effect-free code on the share of `limit`, `spent` of
    /// it already gone to its read at a cut, each effectful unit from its
    /// first effect with the whole limit, a call of this agent's an await.
    /// Its own gas goes to its instance, as a handler's.
    pub(crate) fn workflow(
        &mut self,
        machine: &mut Machine,
        call: Call,
        limit: u64,
        pending: Option<u64>,
        spent: u64,
    ) -> Result<Ended, Failure> {
        set_gas(machine, limit.saturating_sub(spent));
        // A read's kernel run is the step's move: a share it left spent
        // preempts the step, its statement kept.
        let mut share = Share {
            limit,
            allotted: limit,
            effectful: false,
            served: spent > 0,
        };
        self.instances.push(InstanceGas {
            instance: call.instance,
            gas: 0,
        });
        self.nested.push(0);
        let ended = self.units(machine, call, &mut share, pending);
        let nested = self.nested.pop().expect("the workflow's entry");
        self.gas_used = share.used(machine);
        self.instances[0].gas += self.gas_used - nested;
        ended
    }

    fn units(
        &mut self,
        machine: &mut Machine,
        call: Call,
        share: &mut Share,
        pending: Option<u64>,
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        let mut next = pending.map(ExitReason::HostCall);
        loop {
            if let Some(Ended::Paused(_) | Ended::Preempted { .. }) = outcome {
                return Ok(outcome.take().expect("paused"));
            }
            let exit = match next.take() {
                Some(exit) => exit,
                None => machine.try_resume().map_err(|_| Failure::Trapped)?,
            };
            match exit {
                // A section never outlives the workflow's run.
                ExitReason::Halt if self.section => return Err(Failure::Trapped),
                ExitReason::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                // The share is spent: the gas a host leaves after an
                // out-of-gas exit is its own.
                ExitReason::OutOfGas => {
                    set_gas(machine, 0);
                    return preempt_or_fail(share, true, None, !share.served);
                }
                ExitReason::HostCall(id) => {
                    self.unit_call(machine, call, share, id, &mut outcome)?;
                }
                _ => return Err(Failure::Trapped),
            }
        }
    }

    /// Serve host call `id` in its unit, or end the step at it unserved,
    /// or at the await it is, setting `outcome`.
    fn unit_call(
        &mut self,
        machine: &mut Machine,
        call: Call,
        share: &mut Share,
        id: u64,
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let op = Op::from_id(id);
        if op.is_some_and(|op| !abi::workflow_may_use(self.section, op)) {
            return Err(Failure::Trapped);
        }
        let used = share.used(machine);
        if op.is_some_and(abi::is_effect) && !share.effectful {
            if self.kit.uncovered && used > 0 {
                *outcome = Some(preempt_or_fail(share, true, Some(id), false)?);
                return Ok(());
            }
            share.allotted = used + share.limit;
            set_gas(machine, share.limit);
            share.effectful = true;
        }
        let result = if vos_pvm::precompile::is_precompile(id) {
            precompile(machine, id)
        } else if let Some(op) = op {
            if machine.charge(price::of(op)) {
                self.operation(machine, op, call, Kind::Workflow, outcome)
            } else {
                Err(Failure::OutOfGas)
            }
        } else if machine.charge(price::OPERATION) {
            machine.registers_mut()[7] = code::WHAT;
            Ok(())
        } else {
            Err(Failure::OutOfGas)
        };
        match result {
            Ok(()) => share.served = true,
            Err(Failure::OutOfGas) if !share.effectful => {
                *outcome = Some(preempt_or_fail(share, used > 0, Some(id), false)?);
                return Ok(());
            }
            Err(code) => return Err(code),
        }
        if op == Some(Op::Call) && outcome.is_none() {
            share.effectful = false;
            let used = share.used(machine);
            if used >= share.limit {
                *outcome = Some(Ended::Preempted {
                    pending: None,
                    idle: false,
                });
                return Ok(());
            }
            set_gas(machine, share.limit - used);
            share.allotted = share.limit;
        }
        Ok(())
    }
}
