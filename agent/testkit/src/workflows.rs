//! The model's workflows: started by a request or a call, stepped by the
//! input that resumes each, and snapshotted between steps as the default
//! agent snapshots them: the counter after the pausing call, the registers,
//! and each page the step wrote that differs from its base.
//!
//! It shares nothing with the agent's capture and restore: the written
//! pages are the interpreter's dirty pages, and a page's base is read from
//! the parsed program. It keeps no meter: of the budget, it knows only a
//! step that could never run in a batch of it.

use std::collections::BTreeMap;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
use vos_wire::abi::{Failure, Kind, cap};
use vos_wire::batch::{Answer, Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, WorkflowId};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Snapshot, Workflow, WorkflowState};
use vos_wire::result::{InstanceGas, Outcome, Outgoing, PAGE, Page, Write};
use vos_wire::{Decode, Encode, defaults};

use crate::{Ended, Run, Step, Testkit, program_hash, split};

/// Where a machine returns to halt, and the top of its stack.
const HALT: u64 = (1 << 32) - (1 << 16);
const STACK_TOP: u64 = (1 << 32) - 2 * (1 << 16) - (1 << 24);

type Rows = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// A page's hash, as a snapshot names it: BLAKE2b-256 of its bytes.
fn hash(page: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(page).into()
}

/// How a step left its workflow: paused, with the pages it stores and their
/// bytes, or ended.
enum Left {
    Paused(WorkflowState, Vec<Page>, Vec<Vec<u8>>, Snapshot),
    Ended(Outcome),
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
    /// holds, its limit and the finish.
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
            <= self.budget
    }

    /// Start `instance`'s workflow `method` for `owner`: `Started` with its
    /// id, the workflow due at once; or failed, as a step that could not
    /// run.
    pub(crate) fn start(
        &mut self,
        owner: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Step {
        self.steps += 1;
        let (outcome, rows) = match self.started(owner, instance, method, arguments) {
            Ok((id, rows)) => (Outcome::Started(id), rows),
            Err(code) => (
                Outcome::Failed {
                    code,
                    detail: Vec::new(),
                },
                Rows::new(),
            ),
        };
        let mut step = Step::consumed(outcome);
        step.writes = split(rows).0;
        self.apply(&step, Vec::new());
        step
    }

    fn started(
        &self,
        owner: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<(WorkflowId, Rows), Failure> {
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
        let blob = installed
            .bound(method, Kind::Workflow)
            .ok_or(Failure::Unknown)?;
        let program = program_hash(blob);
        let parsed = vos_pvm::spi::parse_standard_program(blob).ok_or(Failure::Unloadable)?;
        let layout = parsed.layout(&[]).ok_or(Failure::Unloadable)?;
        let writable = (layout.rw.size + layout.stack.size) / PAGE as u64;
        if writable > cap::WORKFLOW_PAGES as u64 {
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
            owner,
            gas: schema.gas.unwrap_or(self.default_gas).min(self.max_gas),
            writable: writable as u32,
            awaits: 0,
            due: self.time,
            waiter: None,
            state: WorkflowState::Ready(arguments.to_vec()),
            snapshot: None,
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

    /// The step of workflow `id` due at the batch's time: its first, its
    /// deadline's or timer's, or its collection once ended; `None` when it
    /// is not due.
    pub fn due(&mut self, id: WorkflowId) -> Option<Step> {
        let workflow = self.workflow(id)?;
        if workflow.due > self.time {
            return None;
        }
        let resume = match &workflow.state {
            WorkflowState::Ended(_) => {
                let mut rows = Rows::new();
                Self::unfile_due(&mut rows, id, workflow.due);
                rows.insert(keys::workflow(id), None);
                return Some(self.quick(rows));
            }
            WorkflowState::Ready(arguments) => arguments.clone(),
            WorkflowState::Awaiting { .. } => Answer::Failed {
                code: Failure::TimedOut,
                detail: Vec::new(),
            }
            .encode(),
            WorkflowState::Sleeping { .. } => Vec::new(),
        };
        Some(self.step(id, workflow, resume))
    }

    /// The step a row of the due index makes at `at` when it names a
    /// workflow that is gone, or whose record lies elsewhere: the row
    /// deleted.
    pub fn orphan(&mut self, at: u64, id: WorkflowId) -> Step {
        let mut rows = Rows::new();
        Self::unfile_due(&mut rows, id, at);
        self.quick(rows)
    }

    /// A step that runs nothing and writes `rows`.
    fn quick(&mut self, rows: Rows) -> Step {
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        step.writes = split(rows).0;
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
            matches!(workflow.state, WorkflowState::Awaiting { agent, counter, .. }
                if agent == from && counter == awaiting.counter)
        })?;
        Some(self.step(awaiting.workflow, workflow, answer.encode()))
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
            _ => Some(Answer::Failed {
                code: Failure::Unknown,
                detail: Vec::new(),
            }),
        };
        if let Some(answer) = answer {
            step.messages.push(Outgoing {
                to: from,
                body: Body::Reply { awaiting, answer },
            });
        }
        self.apply(&step, Vec::new());
        step
    }

    /// A step of workflow `id` with `resume` as its input; one that could
    /// never run in a batch of the budget fails at once, past a cap.
    fn step(&mut self, id: WorkflowId, mut workflow: Workflow, resume: Vec<u8>) -> Step {
        let index = self.steps;
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        let mut rows = Rows::new();
        if !self.fits(&workflow) {
            let outcome = Outcome::Failed {
                code: Failure::Cap,
                detail: Vec::new(),
            };
            step.outcome = outcome.clone();
            step.pages = self.end(id, &mut workflow, outcome, &mut rows, &mut step);
            step.writes = split(rows).0;
            self.apply(&step, Vec::new());
            return step;
        }
        let mut run = Run::new(self, index, Kind::Workflow);
        run.awaits = Some(Await {
            workflow: id,
            counter: workflow.awaits,
        });
        let left = self.run_step(&mut run, id, &workflow, &resume);
        step.instances = run.instances.clone();
        step.gas_used = run.gas_used;
        let mut stored = Vec::new();
        // The step's effects, kept when it paused or ended with its result.
        let mut keep_effects = |rows: &mut Rows, step: &mut Step| {
            rows.extend(run.frames.pop().expect("the step overlay"));
            step.messages = std::mem::take(&mut run.messages);
            step.attests = std::mem::take(&mut run.attests);
        };
        match left {
            Ok(Left::Paused(state, pages, bytes, snapshot)) => {
                keep_effects(&mut rows, &mut step);
                let at = match state {
                    WorkflowState::Awaiting { deadline, .. } => deadline,
                    WorkflowState::Sleeping { until } => until,
                    _ => unreachable!("a step pauses awaiting or asleep"),
                };
                if let WorkflowState::Awaiting { .. } = state {
                    workflow.awaits += 1;
                }
                Self::move_due(&mut rows, id, &mut workflow, at);
                workflow.state = state;
                workflow.snapshot = Some(snapshot);
                rows.insert(keys::workflow(id), Some(workflow.encode()));
                step.pages = pages;
                stored = bytes;
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
                let outcome = Outcome::Failed {
                    code,
                    detail: Vec::new(),
                };
                step.outcome = outcome.clone();
                step.pages = self.end(id, &mut workflow, outcome, &mut rows, &mut step);
            }
        }
        (step.writes, step.committed) = split(rows);
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
            step.messages.push(Outgoing {
                to: owner,
                body: Body::Reply {
                    awaiting,
                    answer: outcome.clone().into(),
                },
            });
        }
        workflow.state = WorkflowState::Ended(outcome);
        rows.insert(keys::workflow(id), Some(workflow.encode()));
        pages
    }

    /// Restore workflow `id`'s machine, run it through the step with
    /// `resume` as its input, and capture it if it paused.
    fn run_step(
        &self,
        run: &mut Run,
        id: WorkflowId,
        workflow: &Workflow,
        resume: &[u8],
    ) -> Result<Left, Failure> {
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
        let registers = machine.registers_mut();
        *registers = [0; 13];
        (registers[0], registers[1]) = (HALT, STACK_TOP);
        if let Some(snapshot) = &workflow.snapshot {
            registers.copy_from_slice(&snapshot.registers);
            for (index, hash) in &snapshot.pages {
                let bytes = &self.pages[&(id, *index)];
                assert_eq!(self::hash(bytes), *hash, "a stored page's hash");
                assert!(
                    machine
                        .memory_mut()
                        .write_bytes_checked(index * PAGE as u32, bytes)
                );
            }
        }
        machine.registers_mut()[7] = resume.len() as u64;
        machine.registers_mut()[8] = 0;
        machine.memory_mut().take_dirty_pages();
        let ended = run.workflow(&mut machine, workflow.owner, workflow.instance, resume)?;
        let state = match ended {
            Ended::Paused(state) => state,
            Ended::Replied(result) => return Ok(Left::Ended(Outcome::Done(result))),
            Ended::Failed(detail) => {
                return Ok(Left::Ended(Outcome::Failed {
                    code: Failure::Handler,
                    detail,
                }));
            }
            Ended::Forbidden => unreachable!("a workflow is never refused"),
        };
        // The pages the step wrote, among those the program may write.
        let runs = [layout.rw, layout.stack]
            .map(|region| region.base / PAGE as u64..(region.base + region.size) / PAGE as u64);
        let written: Vec<u64> = machine
            .memory_mut()
            .take_dirty_pages()
            .into_iter()
            .flat_map(|range| u64::from(range.start)..u64::from(range.end))
            .filter(|page| runs.iter().any(|run| run.contains(page)))
            .collect();
        if written.len() * PAGE > cap::STEP_PAGES {
            return Err(Failure::Cap);
        }
        let mut now: BTreeMap<u32, [u8; 32]> = workflow
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.pages.iter().copied().collect())
            .unwrap_or_default();
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
                if start < parsed.rw_data.len() {
                    let end = (start + PAGE).min(parsed.rw_data.len());
                    base[..end - start].copy_from_slice(&parsed.rw_data[start..end]);
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
            let hash = hash(&bytes);
            if now.insert(index, hash) != Some(hash) {
                pages.push(Page {
                    workflow: id,
                    index,
                    hash: Some(hash),
                });
                stored.push(bytes);
            }
        }
        if now.len() > cap::HELD_PAGES {
            return Err(Failure::Cap);
        }
        let pending = machine
            .interpreter()
            .pending_host_call()
            .expect("paused at a host call");
        let snapshot = Snapshot {
            counter: pending.resume_pc,
            registers: machine.registers().to_vec(),
            gas: workflow.gas,
            pages: now.into_iter().collect(),
        };
        Ok(Left::Paused(state, pages, stored, snapshot))
    }
}

impl Run<'_> {
    /// Run a workflow's machine, of `instance`'s workflow method, through
    /// its step. Its own gas goes to its instance, as a handler's.
    pub(crate) fn workflow(
        &mut self,
        machine: &mut Machine,
        owner: Principal,
        instance: InstanceId,
        input: &[u8],
    ) -> Result<Ended, Failure> {
        let gas = machine.gas_remaining();
        self.instances.push(InstanceGas { instance, gas: 0 });
        self.nested.push(0);
        let ended = self.serve(machine, owner, instance, Kind::Workflow, input);
        let nested = self.nested.pop().expect("the workflow's entry");
        self.gas_used = gas - machine.gas_remaining();
        self.instances[0].gas += self.gas_used - nested;
        ended
    }
}
