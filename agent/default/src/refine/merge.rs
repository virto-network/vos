//! A merge: an operation on a device, with no log (`core-model.md` §9.2).
//! Its `#[msg(merge)]` handler runs on the state as it stands, as its
//! operation's author, at the time and seed of the device that issued it,
//! and its one step is the work result, which the device applies itself.
//! Every device that applies the operation runs it so, and writes the
//! same entries ([`vos_wire::merge`]). The step writes its instance's
//! merge fields alone: any other method is `Unknown`, and a run that
//! writes another row, reads a merge field or uses an operation beyond
//! its kind's fails `Trapped`, with nothing written.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, Kind};
use vos_wire::batch::Merge;
use vos_wire::ids::{AgentId, Principal};
use vos_wire::result::{InputRef, Outcome, ResultWriter, Run, Step};

use super::Call;
use super::base::{Base, Source};
use super::inputs::{consumed, split_writes};
use super::invocation::Invocation;

pub(crate) fn run(agent: AgentId, merge: Merge) -> Vec<u8> {
    // One invocation, within its handler's limit: nothing to dispatch.
    let base = Base::new(agent, Source::Node, merge.time, merge.seed, u64::MAX);
    let mut result = ResultWriter::new(0, merge.time, merge.seed);
    let run = step(&base, &merge);
    if !result.push(&Step::Ran(run)) {
        let failed = consumed(InputRef::Merge, Outcome::failed(Failure::Cap));
        assert!(result.push(&Step::Ran(failed)), "a failed step fits");
    }
    result.finish(base.section.into_inner())
}

fn step(base: &Base, merge: &Merge) -> Run {
    let call = Call {
        caller: &Principal::Client(merge.origin.author),
        instance: merge.instance,
        method: merge.method,
        arguments: &merge.arguments,
    };
    let mut invocation = Invocation::new(base, 0, Kind::Merge);
    invocation.origin = Some(merge.origin);
    let outcome = invocation.top(call);
    let mut run = consumed(InputRef::Merge, outcome);
    run.instances = core::mem::take(&mut invocation.instances);
    run.gas_used = invocation.gas_used;
    if let Outcome::Done(_) = run.outcome {
        let frame = invocation.frames.pop().expect("the step overlay");
        (run.writes, _) = split_writes(frame);
    }
    run
}
