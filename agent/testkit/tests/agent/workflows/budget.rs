//! The meter and a step's pages: what a refine's budget lets a workflow's
//! step restore, write and store.

use super::*;

/// The meter: pages a unit writes after its first effect cannot end the
/// step there, so a step whose pages overrun the budget then waits for the
/// next batch behind a step that ran a handler, and fails alone, out of
/// gas; before any effect, the step ends at the first page it cannot pay,
/// and is taken. One no batch of the budget could hold fails at once, past
/// a cap.
#[test]
fn the_meter_holds_workflows_steps() {
    let out_of_gas = Outcome::Failed {
        code: Failure::OutOfGas,
        detail: vec![],
    };
    let cap = Outcome::Failed {
        code: Failure::Cap,
        detail: vec![],
    };
    for backend in Node::backends() {
        // A hundred pages after a send, in a batch of 150M.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 150_000_000;
        let increment = flows.actors.method(COUNTER, "increment");
        let handler = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
        let start = flows.start("splurge", (RISK.0, 100 * 4096u32));
        let result = flows.unmodelled(1, vec![handler, start]);
        assert_eq!(result.steps.len(), 2, "the step waits behind the handler");
        assert!(matches!(flows.record(0).state, WorkflowState::Ready(_)));
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![sweep]);
        assert_eq!(due(&result, 0).outcome, out_of_gas, "alone, it fails");
        assert!(due(&result, 0).messages.is_empty(), "its send discarded");
        assert_eq!(ended(&flows.record(0)), &out_of_gas);

        // A hundred pages before any effect: the reply's step is taken,
        // preempted at the first page the budget cannot pay.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 150_000_000;
        let start = flows.start("fill", (RISK.0, vec![4096u32, 100 * 4096]));
        flows.unmodelled(1, vec![start]);
        let handler = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.unmodelled(1, vec![handler, answer]);
        assert_eq!(result.steps.len(), 2, "the reply's step is taken");
        assert!(matches!(flows.record(0).state, WorkflowState::Preempted(_)));

        // A step no batch of the budget could hold fails at once.
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 100_000_000;
        let start = flows.start("compute", (16u32, 1u32));
        let result = flows.batch(1, vec![start]);
        assert_eq!(due(&result, 0).outcome, cap);
        assert_eq!(ended(&flows.record(0)), &cap);
    }
}

/// The pages a step may move, in a refine of the default budget: one that
/// restores most of what a snapshot may hold has room left for a few
/// hundred written, and ends at the first it cannot pay; holding then more
/// than a snapshot may, it fails past the cap.
#[test]
fn restored_and_written_pages_share_the_budget() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let install = flows.install("big");
        flows.batch(1, vec![install]);
        let start = flows.start("fill", (0u32, vec![500 * 4096u32, 450 * 4096]));
        let result = flows.unmodelled(1, vec![start]);
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        let held = flows.record(0).snapshot.unwrap().pages.len();
        assert!((500..=cap::HELD_PAGES).contains(&held), "{held} held");
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![sweep]);
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        assert_eq!(due(&result, 0).outcome, cap);
    }
}

/// A step whose pages would pass what a result's page section holds waits
/// for the next batch, its row due.
#[test]
fn a_result_holds_at_most_its_pages() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.budget = 8_000_000_000;
        let fill = |flows: &mut Flows| flows.start("fill", (0u32, vec![560 * 4096u32]));
        let inputs = (0..8).map(|_| fill(&mut flows)).collect();
        let result = flows.unmodelled(1, inputs);
        let stepped = |result: &WorkResult| {
            result
                .steps
                .iter()
                .filter(|step| {
                    matches!(
                        step,
                        Step::Ran(Run {
                            input: InputRef::Due { .. },
                            ..
                        })
                    )
                })
                .count()
        };
        assert_eq!(stepped(&result), 7, "an eighth's pages would pass the cap");
        assert!(matches!(flows.record(7).state, WorkflowState::Ready(_)));
        let sweep = flows.sweeping(0);
        let result = flows.unmodelled(0, vec![sweep]);
        assert_eq!(stepped(&result), 1);
        assert!(matches!(
            flows.record(7).state,
            WorkflowState::Sleeping { .. }
        ));
    }
}

/// A page section near its cap, of random pages: seven computations each
/// store some 514 pages in one batch of a large budget, and the agent's
/// heap holds the section, reserved once, its pages stored in it as they
/// are compressed. An eighth's would pass the cap, so its step waits.
#[test]
fn a_page_section_near_its_cap_fits_the_heap() {
    let mut flows = Flows::new(Node::new());
    flows.budget = 6_000_000_000;
    let starts = (0..8)
        .map(|_| flows.start("compute", (262_144u32, 1u32)))
        .collect();
    let result = flows.unmodelled(1, starts);
    let stored: usize = result
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Ran(run) => Some(run.pages.len()),
            _ => None,
        })
        .sum();
    let cap = cap::RESULT_PAGES / vos_wire::result::PAGE;
    assert!(stored > 3 * cap / 4 && stored <= cap, "{stored} pages");
    assert!(matches!(flows.record(7).state, WorkflowState::Ready(_)));
    let sweep = flows.sweeping(1);
    flows.unmodelled(1, vec![sweep]);
    assert!(matches!(
        flows.record(7).state,
        WorkflowState::Sleeping { .. }
    ));
}
