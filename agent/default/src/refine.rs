//! Refine: a batch's inputs as steps, each an actor invocation served
//! against overlays of this refine's writes, or a workflow's step; or a
//! query on applied state. On JAM, a batch comes as a package with the
//! witness of the state it touches ([`jam`]).

mod admin;
mod base;
mod batch;
mod inputs;
mod invocation;
mod jam;
mod sessions;
mod snapshots;
mod workflows;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use vos_wire::abi::Kind;
use vos_wire::batch::{Query, Work};
use vos_wire::ids::AgentId;
use vos_wire::jam::RefineArgs;
use vos_wire::result::{Outcome, PageSection};
use vos_wire::{Decode, Encode};

use base::{Base, Meter, Source};
use batch::run_batch;
use invocation::Invocation;

type Overlay = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

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
