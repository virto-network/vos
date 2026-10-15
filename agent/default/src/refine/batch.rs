//! A batch's inputs as steps, within its budget: each planned against the
//! meter, run, and taken into the result.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Range;

use vos_wire::abi::Failure;
use vos_wire::batch::{Batch, Body, Input, Message};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, WorkflowId};
use vos_wire::records::{SessionMark, Workflow};
use vos_wire::result::{ResultWriter, Run, Step};
use vos_wire::{defaults, keys};

use super::admin::admin;
use super::Call;
use super::base::Base;
use super::inputs::{acknowledge, called, failed_in_refine, message, out_of_order, sweep};
use super::sessions::{ByName, Counts, Held, admit, by_name};
use super::workflows::{self, Floor};
use crate::host::gas;

/// A mark a step advances once it is in the result.
pub(crate) enum Mark {
    Session(Session, Held),
    Pair(AgentId, u64),
}

/// A step as the batch takes it: what the result records, the mark it
/// advances, where in the section lie the pages it stores, and the
/// workflows due after it, a start's or a sweep's, each with the time its
/// row in the due index lies at.
pub(crate) struct Stepped {
    pub(crate) step: Step,
    pub(crate) mark: Option<Mark>,
    pub(crate) pages: Vec<Range<usize>>,
    pub(crate) due: Vec<(u64, WorkflowId)>,
}

impl Stepped {
    pub(crate) fn new(step: Step, mark: Option<Mark>) -> Self {
        Self {
            step,
            mark,
            pages: Vec::new(),
            due: Vec::new(),
        }
    }

    /// A step that ran, advancing no mark.
    pub(crate) fn ran(run: Run) -> Self {
        Self::new(Step::Ran(run), None)
    }
}

/// What a batch has taken so far: the marks, sessions and counts its
/// steps moved, and the result.
pub(crate) struct Batched {
    sessions: BTreeMap<ByName, Held>,
    pairs: BTreeMap<AgentId, u64>,
    counts: Counts,
    /// Whether a step in the result ran a handler or a workflow.
    handled: bool,
    pub(crate) result: ResultWriter,
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
    pub(crate) fn take(
        &mut self,
        base: &mut Base,
        stepped: Stepped,
        reserve: u64,
        handler: bool,
    ) -> Option<Vec<(u64, WorkflowId)>> {
        let overrun = base.meter.overran();
        let section = base.section.get_mut();
        if (overrun && self.handled) || !section.fits() || !self.result.push(&stepped.step) {
            section.drop_running();
            return None;
        }
        section.take();
        let Step::Ran(run) = &stepped.step else {
            base.meter.spend(reserve);
            return Some(stepped.due);
        };
        self.handled |= handler;
        base.meter.spend(reserve + run.gas_used);
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
    if !base.meter.keeps(reserve + defaults::FINISH_RESERVE) {
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
pub(crate) fn run_batch(base: &mut Base, batch: Batch) -> ResultWriter {
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
        if !base.meter.keeps(kept) {
            break;
        }
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
                        let call = Call {
                            caller: request.caller,
                            instance: request.instance,
                            method: request.method,
                            arguments: &request.arguments,
                        };
                        let mut stepped = called(base, index, input, call);
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
