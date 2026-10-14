//! Workflows: their table and their steps.
//!
//! A workflow's record (`keys::workflow`) holds its program, owner, state
//! and snapshot ([`super::snapshots`]). A workflow that has not ended pins
//! its program and counts toward the agent's live workflows; every
//! workflow has exactly one row in the due index, at its next step's time,
//! or once ended at its collection's.
//!
//! The rows are the agent's own: one that does not decode, or a page that
//! does not match its hash, is data the agent lost, and the refine stops
//! ([`lost`]) rather than charge the workflow or its owner with it.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, Kind, cap};
use vos_wire::batch::{Answer, Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, WorkflowId};
use vos_wire::keys::{self, Due};
use vos_wire::records::{Snapshot, Workflow, WorkflowState};
use vos_wire::result::{InputRef, Outcome, Outgoing, Page, Run, Step};
use vos_wire::{Decode, Encode, defaults};

use super::invocation::{Ended, Invocation, Pause};
use super::snapshots::{Captured, capture, restore};
use super::{Base, Batched, Overlay, Stepped, consumed, split_writes};
use crate::host::lost;
use crate::machines;

/// A workflow's record as this refine sees it.
fn record(base: &Base, id: WorkflowId) -> Option<Workflow> {
    let Ok(bytes) = base.read(&keys::workflow(id)) else {
        lost("a workflow's record");
    };
    let bytes = bytes?;
    match Workflow::decode(&bytes) {
        Ok((workflow, _)) if workflow.format == Workflow::FORMAT => Some(workflow),
        _ => lost("a workflow's record"),
    }
}

/// [`record`], paid first by its length, as an installed record is: out of
/// gas when the meter cannot pay it.
fn paid(base: &Base, id: WorkflowId) -> Result<Option<Workflow>, Failure> {
    let key = keys::workflow(id);
    let len = match base.earlier.get(&key) {
        Some(value) => value.as_ref().map_or(0, Vec::len),
        None => crate::host::state_read_into(&key, &mut []).unwrap_or(0),
    };
    if !base.meter.take(defaults::RECORD_BYTE * len as u64) {
        return Err(Failure::OutOfGas);
    }
    Ok(record(base, id))
}

/// The workflow a reply from `from` resumes: the one awaiting it, at the
/// await it names. A reply for an await that is gone, or from another
/// agent, resumes none, and is consumed and dropped.
pub(super) fn resumed(
    base: &Base,
    from: AgentId,
    awaiting: &Await,
) -> Result<Option<Workflow>, Failure> {
    Ok(paid(base, awaiting.workflow)?.filter(|workflow| {
        matches!(workflow.state, WorkflowState::Awaiting { agent, counter, .. }
            if agent == from && counter == awaiting.counter)
    }))
}

/// What the agent keeps of the meter for a step of `workflow`, and takes
/// for it, beside its gas limit: its own work, arming every page the
/// program may write, and restoring every page it holds. Each page the step
/// writes is taken as it is written ([`defaults::WRITTEN_PAGE`]). `None`
/// when the step could never run in a batch of this budget, behind a
/// sweep.
pub(super) fn kept(base: &Base, workflow: &Workflow) -> Option<(u64, u64)> {
    let held = workflow
        .snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.pages.len());
    let reserve = defaults::WORKFLOW_RESERVE
        + u64::from(workflow.writable) * defaults::ARM_PAGE
        + held as u64 * defaults::RESTORED_PAGE;
    let whole = reserve + workflow.gas + defaults::FINISH_RESERVE + defaults::SWEEP_RESERVE;
    (whole <= base.budget).then_some((reserve, workflow.gas))
}

/// Whether `method` of `instance` is a workflow, which a request or a
/// call starts instead of running.
pub(super) fn is_start(base: &Base, instance: InstanceId, method: MethodId) -> bool {
    matches!(
        base.installed(instance),
        Ok(Some(installed)) if installed
            .schema
            .method(method)
            .is_some_and(|schema| schema.kind == Kind::Workflow)
    )
}

/// A count the agent keeps under `key`, 0 when absent.
fn count(base: &Base, key: &[u8]) -> u64 {
    match base.read(key) {
        Ok(None) => 0,
        Ok(Some(bytes)) => match u64::decode(&bytes) {
            Ok((count, _)) => count,
            Err(_) => lost("a workflows' count"),
        },
        Err(_) => lost("a workflows' count"),
    }
}

/// Set a count, its row gone at 0.
fn set_count(rows: &mut Overlay, key: Vec<u8>, count: u64) {
    rows.insert(key, (count > 0).then(|| count.encode()));
}

/// File workflow `id`'s row in the due index at `at`.
fn file_due(rows: &mut Overlay, id: WorkflowId, at: u64) {
    rows.insert(keys::due(at, Due::Workflow(id)), Some(Vec::new()));
}

/// Take workflow `id`'s row at `at` out of the due index.
fn unfile_due(rows: &mut Overlay, id: WorkflowId, at: u64) {
    rows.insert(keys::due(at, Due::Workflow(id)), None);
}

/// Move `workflow`'s row in the due index to `at`.
fn move_due(rows: &mut Overlay, id: WorkflowId, workflow: &mut Workflow, at: u64) {
    if workflow.due != at {
        unfile_due(rows, id, workflow.due);
        file_due(rows, id, at);
        workflow.due = at;
    }
}

/// The pages a program may write: its read-write data and heap, and its
/// stack.
fn writable(header: &vos_pvm_program::StandardHeader) -> Option<u64> {
    let [_, rw, stack] = header.regions()?;
    Some((rw.size + stack.size) / vos_wire::result::PAGE as u64)
}

/// A request's or a call's start of a workflow by `caller`, its owner: the
/// workflow recorded, due at once, its program pinned, and the step
/// answered `Started` with its id; or failed, as a handler's step that
/// could not run fails.
pub(super) fn start(
    base: &Base,
    input: InputRef,
    caller: Principal,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> (Run, Option<WorkflowId>) {
    match started(base, caller, instance, method, arguments) {
        Ok((id, rows)) => {
            let mut run = consumed(input, Outcome::Started(id));
            run.writes = split_writes(rows).0;
            (run, Some(id))
        }
        Err(code) => {
            let outcome = Outcome::Failed {
                code,
                detail: Vec::new(),
            };
            (consumed(input, outcome), None)
        }
    }
}

fn started(
    base: &Base,
    caller: Principal,
    instance: InstanceId,
    method: MethodId,
    arguments: &[u8],
) -> Result<(WorkflowId, Overlay), Failure> {
    if arguments.len() > cap::REQUEST {
        return Err(Failure::Cap);
    }
    let installed = base.installed(instance)?.ok_or(Failure::Unknown)?;
    let schema = installed.schema.method(method).ok_or(Failure::Unknown)?;
    if let Some(role) = &schema.role {
        let required = installed.role(role).expect("checked at install");
        if base.role(&caller)? != Some(required) {
            return Err(Failure::Forbidden);
        }
    }
    let program = installed
        .bound(method, Kind::Workflow)
        .ok_or(Failure::Unknown)?;
    let header = machines::header(&program.0).ok_or(Failure::Unloadable)?;
    let writable = writable(&header).ok_or(Failure::Unloadable)?;
    if writable > cap::WORKFLOW_PAGES as u64 {
        return Err(Failure::Cap);
    }
    let live = count(base, &keys::live_workflows());
    if live >= defaults::MAX_WORKFLOWS {
        return Err(Failure::Cap);
    }
    let id = WorkflowId(count(base, &keys::next_workflow()));
    let pins = count(base, &keys::workflow_pins(&program));
    let workflow = Workflow {
        format: Workflow::FORMAT,
        program,
        instance,
        owner: caller,
        gas: schema
            .gas
            .unwrap_or(defaults::HANDLER_GAS)
            .min(defaults::MAX_HANDLER_GAS),
        writable: writable as u32,
        awaits: 0,
        due: base.time,
        waiter: None,
        state: WorkflowState::Ready(arguments.to_vec()),
        snapshot: None,
    };
    let mut rows = Overlay::new();
    set_count(&mut rows, keys::next_workflow(), id.0 + 1);
    set_count(&mut rows, keys::live_workflows(), live + 1);
    set_count(&mut rows, keys::workflow_pins(&program), pins + 1);
    file_due(&mut rows, id, workflow.due);
    rows.insert(keys::workflow(id), Some(workflow.encode()));
    Ok((id, rows))
}

/// The step of workflow `id` due in this batch by its row at `at`, run if
/// the meter keeps what it needs: its first, a deadline's or a timer's, or
/// its collection. One the budget cannot hold now waits, its row due
/// still, for a later batch. A row whose workflow is gone, or whose record
/// lies elsewhere, is deleted.
pub(super) fn due(base: &mut Base, batched: &mut Batched, at: u64, id: WorkflowId) {
    base.meter
        .kept
        .set(defaults::INPUT_RESERVE + defaults::FINISH_RESERVE);
    if base.meter.left.get() < base.meter.kept.get() {
        return;
    }
    let Ok(workflow) = paid(base, id) else {
        base.meter.overrun.set(false);
        return;
    };
    let input = InputRef::Due { workflow: id };
    let quick = |run| Stepped::new(Step::Ran(run), None);
    let (stepped, reserve, handler) = match workflow {
        Some(workflow) if workflow.due == at => match &workflow.state {
            WorkflowState::Ended(_) => (
                quick(collect(input, id, &workflow)),
                defaults::INPUT_RESERVE,
                false,
            ),
            state => {
                let resume = match state {
                    WorkflowState::Ready(arguments) => arguments.clone(),
                    WorkflowState::Awaiting { .. } => Answer::Failed {
                        code: Failure::TimedOut,
                        detail: Vec::new(),
                    }
                    .encode(),
                    _ => Vec::new(),
                };
                let reserve = match kept(base, &workflow) {
                    Some((reserve, limit)) => {
                        let kept = reserve + limit + defaults::FINISH_RESERVE;
                        if base.meter.left.get() < kept {
                            return;
                        }
                        base.meter.kept.set(kept);
                        reserve
                    }
                    None => defaults::INPUT_RESERVE,
                };
                let index = batched.result.count();
                (
                    resume_step(base, index, input, id, workflow, resume),
                    reserve,
                    true,
                )
            }
        },
        // An orphan, or a row the record has moved from.
        _ => {
            let mut run = consumed(input, Outcome::Done(Vec::new()));
            let mut rows = Overlay::new();
            unfile_due(&mut rows, id, at);
            run.writes = split_writes(rows).0;
            (quick(run), defaults::INPUT_RESERVE, false)
        }
    };
    batched.take(base, stepped, reserve, handler);
}

/// An ended workflow's collection, once its result has been kept long
/// enough: its record and its row in the due index go.
fn collect(input: InputRef, id: WorkflowId, workflow: &Workflow) -> Run {
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    let mut rows = Overlay::new();
    unfile_due(&mut rows, id, workflow.due);
    rows.insert(keys::workflow(id), None);
    run.writes = split_writes(rows).0;
    run
}

/// A wait from agent `from` for the result of workflow `id`, at its await
/// `awaiting`: answered with the result once the workflow ends, at once if
/// it has; only its owner may wait, any other is answered `Unknown`.
pub(super) fn wait(
    base: &Base,
    input: InputRef,
    from: AgentId,
    id: WorkflowId,
    awaiting: Await,
) -> Run {
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    let failed = |code| Answer::Failed {
        code,
        detail: Vec::new(),
    };
    let answer = match paid(base, id) {
        Ok(Some(mut workflow)) if workflow.owner == Principal::Agent(from) => {
            match &workflow.state {
                WorkflowState::Ended(outcome) => Some(outcome.clone().into()),
                _ => {
                    workflow.waiter = Some(awaiting);
                    run.writes.push(vos_wire::result::Write {
                        key: keys::workflow(id),
                        value: Some(workflow.encode()),
                    });
                    None
                }
            }
        }
        Ok(_) => Some(failed(Failure::Unknown)),
        // The meter could not pay the record: as an overrun, the wait
        // waits behind a step that ran a handler, or fails alone.
        Err(code) => {
            run.outcome = Outcome::Failed {
                code,
                detail: Vec::new(),
            };
            Some(failed(code))
        }
    };
    if let Some(answer) = answer {
        run.messages.push(Outgoing {
            to: from,
            body: Body::Reply { awaiting, answer },
        });
    }
    run
}

/// How a workflow's step left it.
enum Left {
    /// Paused, its machine captured.
    Paused {
        pause: Pause,
        captured: Captured,
        counter: u32,
        registers: Vec<u64>,
    },
    /// Ended with its result, or its own error.
    Ended(Outcome),
    /// Failed: it trapped, ran out of gas or passed a cap.
    Failed(Failure),
}

/// A step of workflow `id` resumed by `input`, with `resume` its encoded
/// input: run, or, when it could never run in a batch of this budget,
/// failed at once with [`Failure::Cap`].
pub(super) fn resume_step(
    base: &Base,
    index: u32,
    input: InputRef,
    id: WorkflowId,
    workflow: Workflow,
    resume: Vec<u8>,
) -> Stepped {
    if kept(base, &workflow).is_none() {
        return unfit(base, input, id, workflow);
    }
    step(base, index, input, id, workflow, resume)
}

/// Fail a workflow whose step could never run in a batch of this budget.
fn unfit(base: &Base, input: InputRef, id: WorkflowId, mut workflow: Workflow) -> Stepped {
    let outcome = Outcome::Failed {
        code: Failure::Cap,
        detail: Vec::new(),
    };
    let mut run = consumed(input, outcome.clone());
    let mut rows = Overlay::new();
    run.pages = end(base, id, &mut workflow, outcome, &mut rows, &mut run);
    run.writes = split_writes(rows).0;
    Stepped::new(Step::Ran(run), None)
}

/// Restore workflow `id`'s machine, run it through its step with `resume`
/// as its input, and capture it if it paused.
fn run(
    base: &Base,
    invocation: &mut Invocation,
    id: WorkflowId,
    workflow: &Workflow,
    resume: &[u8],
) -> Left {
    let (mut machine, header) = match restore(base, id, workflow) {
        Ok(restored) => restored,
        Err(code) => return Left::Failed(code),
    };
    machine.set_register(7, resume.len() as u64);
    machine.set_register(8, 0);
    let ended = invocation.workflow(&mut machine, workflow.owner, workflow.instance, resume);
    match ended {
        Ok(Ended::Paused(pause)) => {
            let held = workflow
                .snapshot
                .as_ref()
                .map_or(&[][..], |snapshot| &snapshot.pages);
            match capture(&machine, &workflow.program, &header, id, held) {
                Ok(captured) => Left::Paused {
                    pause,
                    captured,
                    registers: (0..13).map(|index| machine.register(index)).collect(),
                    counter: machine.expunge() as u32,
                },
                Err(code) => Left::Failed(code),
            }
        }
        Ok(Ended::Replied(result)) => Left::Ended(Outcome::Done(result)),
        Ok(Ended::Failed(detail)) => Left::Ended(Outcome::Failed {
            code: Failure::Handler,
            detail,
        }),
        Ok(Ended::Forbidden) => unreachable!("a workflow is never refused"),
        Err(code) => Left::Failed(code),
    }
}

/// A step of workflow `id`, resumed by `input` with `resume`, its encoded
/// input: restored, run until it pauses, ends or fails, and captured.
///
/// Its calls' effects, its messages and its snapshot commit together. A
/// step that traps, runs out of gas or exceeds a cap fails the workflow:
/// its effects are discarded, its input is still consumed, and the
/// workflow ends as failed, its pin and pages gone and its owner told. A
/// workflow that returns its error ends so too, as a handler's error
/// discards its step's effects.
fn step(
    base: &Base,
    index: u32,
    input: InputRef,
    id: WorkflowId,
    mut workflow: Workflow,
    resume: Vec<u8>,
) -> Stepped {
    let mut invocation = Invocation::new(base, index, Kind::Workflow);
    invocation.awaits = Some(Await {
        workflow: id,
        counter: workflow.awaits,
    });
    let left = run(base, &mut invocation, id, &workflow, &resume);
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    run.instances = core::mem::take(&mut invocation.instances);
    run.gas_used = invocation.gas_used;
    let mut rows = Overlay::new();
    let mut stored = Vec::new();
    // The step's effects, kept when it paused or ended with its result.
    let keep_effects = |invocation: Invocation, rows: &mut Overlay, run: &mut Run| {
        let Invocation {
            mut frames,
            messages,
            attests,
            ..
        } = invocation;
        rows.extend(frames.pop().expect("the step overlay"));
        run.messages = messages;
        run.attests = attests;
    };
    match left {
        Left::Paused {
            pause,
            captured,
            counter,
            registers,
        } => {
            keep_effects(invocation, &mut rows, &mut run);
            if let Pause::Await { .. } = pause {
                workflow.awaits += 1;
            }
            move_due(&mut rows, id, &mut workflow, pause.due());
            workflow.state = pause.state();
            workflow.snapshot = Some(Snapshot {
                counter,
                registers,
                gas: workflow.gas,
                pages: captured.held,
            });
            rows.insert(keys::workflow(id), Some(workflow.encode()));
            run.pages = captured.pages;
            stored = captured.stored;
        }
        Left::Ended(outcome) => {
            if let Outcome::Done(_) = outcome {
                keep_effects(invocation, &mut rows, &mut run);
            } else {
                run.outcome = outcome.clone();
            }
            run.pages = end(base, id, &mut workflow, outcome, &mut rows, &mut run);
        }
        Left::Failed(code) => {
            let outcome = Outcome::Failed {
                code,
                detail: Vec::new(),
            };
            run.outcome = outcome.clone();
            run.pages = end(base, id, &mut workflow, outcome, &mut rows, &mut run);
        }
    }
    let (writes, committed) = split_writes(rows);
    run.writes = writes;
    run.committed = committed;
    let mut stepped = Stepped::new(Step::Ran(run), None);
    stepped.pages = stored;
    stepped
}

/// End `workflow` with `outcome`: its pages dropped, its pin and its place
/// among the live workflows released, its row in the due index moved to
/// its collection, and its owner told when it waits. Returns the dropped
/// pages' entries.
fn end(
    base: &Base,
    id: WorkflowId,
    workflow: &mut Workflow,
    outcome: Outcome,
    rows: &mut Overlay,
    run: &mut Run,
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
    let pinned = count(base, &pins);
    set_count(rows, pins, pinned.saturating_sub(1));
    let live = count(base, &keys::live_workflows());
    set_count(rows, keys::live_workflows(), live.saturating_sub(1));
    let collected = base.time.saturating_add(defaults::WORKFLOW_KEPT_MS);
    move_due(rows, id, workflow, collected);
    if let (Some(awaiting), Principal::Agent(owner)) = (workflow.waiter.take(), workflow.owner) {
        run.messages.push(Outgoing {
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
