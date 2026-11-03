//! A merge: a device's call, with no log (`core-model.md` §9.2). Its
//! handler runs as a command's step does, on the state as it stands, and
//! its one step is the work result, which the device applies itself. The
//! step may only write rows: a run that sends a message, attests or writes
//! a committed map, or a call that would start a workflow, fails
//! `Trapped`, with nothing written.

use alloc::vec::Vec;

use vos_wire::abi::Failure;
use vos_wire::batch::Merge;
use vos_wire::ids::AgentId;
use vos_wire::result::{InputRef, Outcome, ResultWriter, Run, Step};

use super::Call;
use super::base::{Base, Source};
use super::inputs::{command, consumed};
use super::workflows;

pub(crate) fn run(agent: AgentId, merge: Merge) -> Vec<u8> {
    // One invocation, within its handler's limit: nothing to dispatch.
    let base = Base::new(agent, Source::Node, merge.time, merge.seed, u64::MAX);
    let mut result = ResultWriter::new(merge.version, merge.time, merge.seed);
    let run = step(&base, &merge);
    if !result.push(&Step::Ran(run)) {
        let failed = consumed(InputRef::Merge, Outcome::failed(Failure::Cap));
        assert!(result.push(&Step::Ran(failed)), "a failed step fits");
    }
    result.finish(base.section.into_inner())
}

fn step(base: &Base, merge: &Merge) -> Run {
    let trapped = || consumed(InputRef::Merge, Outcome::failed(Failure::Trapped));
    if workflows::is_start(base, merge.instance, merge.method) {
        return trapped();
    }
    let call = Call {
        caller: &merge.caller,
        instance: merge.instance,
        method: merge.method,
        arguments: &merge.arguments,
    };
    let run = command(base, 0, InputRef::Merge, call);
    if run.messages.is_empty() && run.attests.is_empty() && run.committed.is_empty() {
        return run;
    }
    Run {
        instances: run.instances,
        gas_used: run.gas_used,
        ..trapped()
    }
}
