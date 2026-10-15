//! Each input's step: a request's or a call's, a message's, an
//! acknowledgement's and a sweep's.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vos_wire::abi::{Failure, Kind, Refusal};
use vos_wire::batch::{Await, Body, Message};
use vos_wire::ids::{AgentId, Principal};
use vos_wire::keys::Due;
use vos_wire::records::Workflow;
use vos_wire::result::{CommittedWrite, InputRef, Outcome, Outgoing, Run, Step, Write};
use vos_wire::{Encode, defaults, keys};

use super::{Call, Overlay};
use super::base::{Base, Corrupt};
use super::batch::{Mark, Stepped};
use super::invocation::Invocation;
use super::workflows;

/// A request's or a call's step: a handler's command, or a workflow's
/// start, which its first step follows when the budget allows.
pub(crate) fn called(base: &Base, index: u32, input: InputRef, call: Call) -> Stepped {
    if workflows::is_start(base, call.instance, call.method) {
        let (run, started) = workflows::start(base, input, call);
        let mut stepped = Stepped::ran(run);
        stepped
            .due
            .extend(started.map(|workflow| (base.time, workflow)));
        return stepped;
    }
    let run = command(base, index, input, call);
    Stepped::ran(run)
}

/// Why a message from `from` at `sequence` is out of its pair's order, if
/// it is.
pub(crate) fn out_of_order(
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
pub(crate) fn message(
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
            let call = Call {
                caller: Principal::Agent(from),
                instance,
                method,
                arguments: &arguments,
            };
            let mut stepped = called(base, index, input, call);
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
            None => Stepped::ran(consumed(input, Outcome::Done(Vec::new()))),
        },
        Body::Wait { workflow, awaiting } => {
            let run = workflows::wait(base, input, from, workflow, awaiting);
            Stepped::ran(run)
        }
    };
    stepped.mark = Some(Mark::Pair(from, sequence));
    stepped
}

/// A message the leader asserts failed in refine, in its pair's order:
/// consumed as failed without running, and answered when it awaits.
pub(crate) fn failed_in_refine(
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
pub(crate) fn consumed(input: InputRef, outcome: Outcome) -> Run {
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

fn command(base: &Base, index: u32, input: InputRef, call: Call) -> Run {
    let mut invocation = Invocation::new(base, index, Kind::Command);
    let outcome = invocation.top(call);
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
pub(crate) fn split_writes(overlay: Overlay) -> (Vec<Write>, Vec<CommittedWrite>) {
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

/// An acknowledgement from agent `to`: unsequenced, never refused, and
/// it runs no actor. Accumulate clears the outbox through `sequence`.
pub(crate) fn acknowledge(to: AgentId, sequence: u64) -> Step {
    Step::Ran(consumed(
        InputRef::Ack { to, sequence },
        Outcome::Done(Vec::new()),
    ))
}

/// The rows of the due index the leader listed, each still there and due
/// at the batch's time: the sessions among them, each its row's time and
/// id, for accumulate to collect or file again, and the workflows, whose
/// steps follow. A row not there, or not due, is passed over.
pub(crate) fn sweep(base: &Base, listed: &[(u64, Due)]) -> Stepped {
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
