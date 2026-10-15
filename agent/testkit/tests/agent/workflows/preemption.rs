//! Preemption: a workflow's step ends between two awaits when its share is
//! spent, at the start of a block, at a first effect the refine cannot give
//! the step's limit, at a page the meter cannot pay, or at a call of this
//! agent's once the share is spent; the next step continues it. A step that
//! cannot move fails instead.

use super::*;
use vos_wire::abi::{op, precompile};

/// What a step of workflow `id` keeps of the meter, its record's read
/// included: a batch's budget past it is the step's room.
fn keep(flows: &Flows, id: u64) -> u64 {
    let record = flows.record(id);
    let held = record
        .snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.pages.len());
    let stored = flows.node.state[&keys::workflow(WorkflowId(id))].len() as u64;
    defaults::RECORD_BYTE * stored
        + defaults::WORKFLOW_RESERVE
        + u64::from(record.writable) * defaults::ARM_PAGE
        + held as u64 * defaults::RESTORED_PAGE
        + record.gas
        + defaults::FINISH_RESERVE
}

/// A long computation with no await in it: its share preempts it at the
/// start of a block, step after step, each batch's sweep continuing it from
/// its snapshot, and it ends with the result of the run that never
/// stopped. Batches of the default budget, every step the model's.
#[test]
fn a_long_computation_spans_refines_on_its_own() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let arguments = (4096u32, 200u32);
        let start = flows.start("grind_whole", arguments);
        flows.batch(1, vec![start]);
        let whole = ended(&flows.record(0)).clone();
        assert!(matches!(whole, Outcome::Done(_)), "{whole:?}");

        let start = flows.start("grind", arguments);
        let result = flows.batch(1, vec![start]);
        let first = due(&result, 1);
        assert_eq!(first.outcome, Outcome::Done(vec![]));
        let limit = flows.record(1).gas;
        assert!(first.gas_used <= limit, "{} of {limit}", first.gas_used);
        let record = flows.record(1);
        assert_eq!(record.state, WorkflowState::Preempted(arguments.encode()));
        assert_eq!(record.due, flows.time + 1, "due at once");
        assert_eq!(record.awaits, 0);
        assert_eq!(record.snapshot.unwrap().pending, None);
        let mut steps = 1;
        while !matches!(flows.record(1).state, WorkflowState::Ended(_)) {
            let result = flows.sweep(1);
            assert!(due(&result, 1).gas_used <= limit);
            steps += 1;
            assert!(steps < 100, "it ends");
        }
        assert!(steps >= 3, "{steps} steps");
        assert_eq!(ended(&flows.record(1)), &whole);
        assert_eq!(flows.count(&keys::live_workflows()), None);
    }
}

/// A computation whose working set no step can write in full: each step
/// restores the pages the workflow holds and pays again for those it
/// writes, so a step ends at the first page the meter cannot pay, before
/// its share is spent, and the next goes on from there. At the default
/// budget it still moves, step by step, to the result of the run that never
/// stopped.
#[test]
fn a_computation_moves_past_what_one_step_can_write() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        // 540 pages of words, mixed twice.
        let arguments = (276_480u32, 2u32);
        let start = flows.start("grind_whole", arguments);
        flows.unmodelled(1, vec![start]);
        let whole = ended(&flows.record(0)).clone();
        assert!(matches!(whole, Outcome::Done(_)), "{whole:?}");

        let start = flows.start("grind", arguments);
        flows.unmodelled(1, vec![start]);
        let limit = flows.record(1).gas;
        let mut steps = 1;
        let mut short = 0;
        while !matches!(flows.record(1).state, WorkflowState::Ended(_)) {
            let held = flows.record(1).snapshot.unwrap().pages.len();
            assert!((500..=cap::HELD_PAGES).contains(&held), "{held} held");
            // What restoring them leaves the budget for pages written.
            let room = (defaults::REFINE_GAS - defaults::SWEEP_RESERVE - keep(&flows, 1))
                / defaults::WRITTEN_PAGE;
            assert!(room < held as u64, "{room} pages of room");
            let sweep = flows.sweeping(1);
            let result = flows.unmodelled(1, vec![sweep]);
            let run = due(&result, 1);
            let stored = run.pages.iter().filter(|page| page.hash.is_some()).count();
            assert!(stored as u64 <= room, "{stored} pages stored");
            if run.gas_used < limit && matches!(flows.record(1).state, WorkflowState::Preempted(_))
            {
                short += 1;
            }
            steps += 1;
            assert!(steps < 20, "it ends");
        }
        assert!(short >= 1, "a step ended at a page it could not pay");
        assert_eq!(ended(&flows.record(1)), &whole);
    }
}

/// A unit's first effect, after effect-free code that used most of the
/// step's limit, in a batch that cannot give the effectful unit the whole
/// limit beyond it: the step ends at the call, unserved and kept in the
/// snapshot, its input consumed. The next step serves it first, as the
/// unit's first effect, and the sale is counted once.
#[test]
fn a_first_effect_the_refine_cannot_cover_waits_at_its_call() {
    let rounds = settle_rounds();
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("settle", rounds);
        // Room for the limit, not for the limit again past nine tenths.
        flows.budget = SETTLE_LIMIT + SETTLE_LIMIT / 2;
        flows.kit.uncovered = true;
        let result = flows.batch(1, vec![start]);
        flows.kit.uncovered = false;
        let first = due(&result, 0);
        assert_eq!(first.outcome, Outcome::Done(vec![]));
        assert!(first.messages.is_empty() && first.writes.len() > 1);
        let record = flows.record(0);
        assert_eq!(record.gas, SETTLE_LIMIT);
        assert_eq!(record.state, WorkflowState::Preempted(rounds.encode()));
        let snapshot = record.snapshot.unwrap();
        assert_eq!(snapshot.pending, Some(op::CALL));
        assert_eq!(snapshot.registers[8], u64::from(flows.method("sell").0));
        assert_eq!(flows.sales(), 0, "the call waits unserved");

        flows.budget = defaults::REFINE_GAS;
        let result = flows.sweep(1);
        let second = due(&result, 0);
        assert!(second.gas_used < first.gas_used, "{second:?}");
        let sales = u64::from(rounds % 100 + 1);
        assert_eq!(flows.sales(), sales);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(sales.encode()));
    }
}

/// A call of this agent's is an await: once the step's share is spent,
/// the step ends with it, the call's effects committed with the snapshot,
/// and the next step goes on from right after the call.
#[test]
fn a_call_ends_the_step_once_the_share_is_spent() {
    let (rounds, len, times) = relayed(3);
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("relay", (rounds, len, times));
        let result = flows.batch(1, vec![start]);
        let first = due(&result, 0);
        assert_eq!(flows.record(0).gas, RELAY_LIMIT);
        assert!(first.gas_used >= RELAY_LIMIT, "{}", first.gas_used);
        let record = flows.record(0);
        assert!(matches!(record.state, WorkflowState::Preempted(_)));
        assert_eq!(record.snapshot.unwrap().pending, None);
        assert_eq!(flows.sales(), 0, "ended at the echo's await");
        let mut steps = 1;
        let mut sales = vec![0];
        while !matches!(flows.record(0).state, WorkflowState::Ended(_)) {
            flows.sweep(1);
            sales.push(flows.sales());
            steps += 1;
            assert!(steps < 20, "it ends");
        }
        let total = u64::from(times * len);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(total.encode()));
        assert!(steps >= 3, "{steps} steps, sales {sales:?}");
        assert!(sales.windows(2).all(|pair| pair[0] <= pair[1]), "{sales:?}");
    }
}

/// The floor: a step whose machine cannot move on the share it has, its
/// first block past the step's limit, is never preempted, which would pin
/// it at one counter and commit a snapshot every batch: it fails, out of
/// gas, its share spent.
#[test]
fn a_step_that_cannot_move_fails_rather_than_preempts() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("stuck", ());
        let result = flows.batch(1, vec![start]);
        let out_of_gas = Outcome::Failed {
            code: Failure::OutOfGas,
            detail: vec![],
        };
        assert_eq!(due(&result, 0).outcome, out_of_gas);
        assert_eq!(due(&result, 0).gas_used, flows.record(0).gas);
        assert_eq!(ended(&flows.record(0)), &out_of_gas);
    }
}

/// The floor counts a page written as movement: a loop that writes only
/// memory, every pass starting with the same registers, is preempted step
/// after step at the block it resumed at, its registers as they were, so
/// they and its counter alone would call it idle. Its count moves all the
/// same, and it ends with it. Every step the model's.
#[test]
fn a_loop_that_writes_only_memory_moves() {
    let until = 500_000u64;
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("tally", until);
        flows.batch(1, vec![start]);
        let mut last = flows.record(0).snapshot.expect("preempted");
        let (mut steps, mut unmoved) = (1, 0);
        while !matches!(flows.record(0).state, WorkflowState::Ended(_)) {
            flows.sweep(1);
            steps += 1;
            assert!(steps < 60, "it ends");
            let record = flows.record(0);
            let Some(snapshot) = record.snapshot else {
                continue;
            };
            assert!(matches!(record.state, WorkflowState::Preempted(_)));
            if (snapshot.counter, &snapshot.registers) == (last.counter, &last.registers) {
                unmoved += 1;
            }
            last = snapshot;
        }
        assert!(
            unmoved >= 1,
            "{unmoved} of {steps} steps where they resumed"
        );
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(until.encode()));
    }
}

/// An effect-free operation the share cannot pay, a compression: the step
/// ends before it, unserved, and the next step serves it first. The
/// compressions' result is the one computed straight. Every step the
/// model's.
#[test]
fn an_unpaid_compression_waits_for_the_next_step() {
    let rounds = 1_000u32;
    let mut h = [0u64; 8];
    for round in 0..rounds {
        let m = [u64::from_le_bytes([round as u8; 8]); 16];
        let counter = u128::from(round + 1) * 128;
        h = vos_pvm::precompile::compress(&h, &m, counter, round + 1 == rounds);
    }
    let digest: Vec<u8> = h[..4].iter().flat_map(|word| word.to_le_bytes()).collect();
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("press", rounds);
        flows.batch(1, vec![start]);
        assert_eq!(flows.record(0).gas, PRESS_LIMIT);
        let mut pending = 0;
        let mut steps = 1;
        while !matches!(flows.record(0).state, WorkflowState::Ended(_)) {
            let snapshot = flows.record(0).snapshot.unwrap();
            if snapshot.pending == Some(precompile::BLAKE2B_COMPRESS) {
                pending += 1;
            }
            flows.sweep(1);
            steps += 1;
            assert!(steps < 50, "it ends");
        }
        assert!(pending > 0, "a compression waited, in {steps} steps");
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(digest.encode()));
    }
}

/// A large answer resumes a workflow in a batch whose meter cannot pay the
/// pages the answer lands on: the step ends at its `INPUT`, unserved. A
/// batch behind a handler that still cannot pay them leaves it waiting,
/// unmoved; once one can, the next step serves the `INPUT` first, from the
/// answer the workflow keeps, its registers as they were. A step that
/// cannot pay its first page, behind a handler, waits too. The two
/// backends agree on every batch.
#[test]
fn an_unpaid_input_waits_for_its_pages() {
    let mut runs = Vec::new();
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("fill", (RISK.0, vec![4096u32, 4096]));
        flows.batch(1, vec![start]);
        let answer = Answer::Done(vec![9; 60_000]);
        let reply = flows.reply(RISK, 0, 0, answer.clone());
        let mut results = Vec::new();

        // Room for a few pages, not the fifteen the answer lands on.
        flows.budget = keep(&flows, 0) + 8 * defaults::WRITTEN_PAGE;
        results.push(flows.unmodelled(1, vec![reply]));
        let record = flows.record(0);
        assert_eq!(record.state, WorkflowState::Preempted(answer.encode()));
        let snapshot = record.snapshot.unwrap();
        assert_eq!(snapshot.pending, Some(op::INPUT));

        // Behind a handler, the sweep's head with room for a few pages, half
        // of them its floor's: the `INPUT` waits, unserved and unmoved.
        let installed = flows.node.state[&keys::installed(COUNTER)].len() as u64;
        let handler = defaults::STEP_RESERVE + defaults::RECORD_BYTE * installed;
        let unknown = flows.sessions.request(ALICE, COUNTER, MethodId(999), ());
        flows.budget =
            handler + defaults::SWEEP_RESERVE + keep(&flows, 0) + 4 * defaults::WRITTEN_PAGE;
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![unknown, sweep]);
        assert_eq!(result.steps.len(), 2, "the step waits behind the handler");
        assert!(matches!(result.steps[1], Step::Swept { .. }));
        assert_eq!(flows.record(0).snapshot.unwrap(), snapshot);
        results.push(result);

        // With room, the `INPUT` is served first, from the kept answer; and
        // a sleeper starts.
        flows.budget = defaults::REFINE_GAS;
        let sweep = flows.sweeping(1);
        let start = flows.start("fill", (0u32, vec![4096u32, 4096]));
        results.push(flows.unmodelled(1, vec![sweep, start]));
        let record = flows.record(0);
        assert_eq!(record.awaits, 2);
        assert!(matches!(
            record.state,
            WorkflowState::Awaiting { counter: 1, .. }
        ));
        assert!(matches!(
            flows.record(1).state,
            WorkflowState::Sleeping { .. }
        ));

        // The sleeper, the sweep's head behind a handler, in a batch of the
        // least budget its step fits: its floor leaves it less than a
        // page, so its first store waits, unmoved.
        let unknown = flows.sessions.request(ALICE, COUNTER, MethodId(999), ());
        flows.budget = keep(&flows, 1) + defaults::SWEEP_RESERVE + 2 * defaults::WRITTEN_PAGE;
        let sweep = flows.sweeping(1);
        let result = flows.unmodelled(1, vec![unknown, sweep]);
        assert_eq!(
            result.steps.len(),
            2,
            "the sleeper waits behind the handler"
        );
        assert!(matches!(
            flows.record(1).state,
            WorkflowState::Sleeping { .. }
        ));
        results.push(result);
        flows.budget = defaults::REFINE_GAS;
        for _ in 0..2 {
            let sweep = flows.sweeping(1);
            results.push(flows.unmodelled(1, vec![sweep]));
        }
        assert_eq!(ended(&flows.record(1)), &Outcome::Done(8192u64.encode()));
        runs.push(results);
    }
    assert!(runs.windows(2).all(|pair| pair[0] == pair[1]));
}

/// A sweep's due steps leave the batch's inputs their floor: beside two
/// computations that each restore some 540 pages a step, requests in the
/// same batches all run at the default budget. The head computation runs
/// each batch, the other waits for the next sweep, and each moves in turn.
#[test]
fn requests_progress_beside_large_computations() {
    let mut flows = Flows::at_default_budget(Node::new());
    for _ in 0..2 {
        let start = flows.start("grind", (276_480u32, 3u32));
        flows.unmodelled(1, vec![start]);
    }
    let increment = flows.actors.method(COUNTER, "increment");
    let mut steps = [0; 2];
    for _ in 0..6 {
        let mut inputs = vec![flows.sweeping(1)];
        inputs.extend((0..3).map(|_| flows.sessions.request(ALICE, COUNTER, increment, 1u64)));
        let result = flows.unmodelled(1, inputs);
        let requests = result
            .steps
            .iter()
            .filter(|step| {
                matches!(
                    step,
                    Step::Ran(Run {
                        input: InputRef::Request { .. },
                        outcome: Outcome::Done(_),
                        ..
                    })
                )
            })
            .count();
        assert_eq!(requests, 3, "{:?}", result.steps.len());
        for (id, steps) in steps.iter_mut().enumerate() {
            let input = InputRef::Due {
                workflow: WorkflowId(id as u64),
            };
            if result
                .steps
                .iter()
                .any(|step| matches!(step, Step::Ran(run) if run.input == input))
            {
                *steps += 1;
            }
        }
    }
    assert!(steps.iter().all(|&taken| taken >= 2), "{steps:?}");
}

/// A call of this agent's that is its unit's first effect, whose reply
/// lands on a page the meter cannot pay: the call waits, unserved, as its
/// output is kept for before it is served, so its effects never outrun
/// their pages; the next step serves it first. The batch's room is the
/// least that takes the step to the call: the pages its own code writes
/// before, too few for the reply's too.
#[test]
fn a_call_whose_reply_the_meter_cannot_pay_waits_unserved() {
    let (rounds, len, times) = relayed(2);
    let mut runs = Vec::new();
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("relay", (rounds, len, times));
        let mut results = vec![flows.unmodelled(1, vec![start])];
        let sales = flows.sales();
        // The record a step left, as its writes hold it.
        let left = |result: &WorkResult| -> Option<Workflow> {
            let run = due(result, 0);
            let write = run
                .writes
                .iter()
                .find(|write| write.key == keys::workflow(WorkflowId(0)))?;
            vos_wire::Decode::decode(write.value.as_ref()?)
                .ok()
                .map(|(record, _)| record)
        };
        let room = (1..64)
            .find(|&pages| {
                let budget =
                    keep(&flows, 0) + defaults::SWEEP_RESERVE + pages * defaults::WRITTEN_PAGE;
                let work = flows.node.budgeted_work(
                    flows.time + 1,
                    [0; 32],
                    budget,
                    vec![flows.sweeping(1)],
                );
                let output = flows.node.refine_with(&work, budget);
                let result = split_output(&output).unwrap().0;
                left(&result)
                    .and_then(|record| record.snapshot)
                    .is_some_and(|snapshot| snapshot.pending == Some(op::CALL))
            })
            .expect("a room that takes the step to its call");
        flows.budget = keep(&flows, 0) + defaults::SWEEP_RESERVE + room * defaults::WRITTEN_PAGE;
        let sweep = flows.sweeping(1);
        results.push(flows.unmodelled(1, vec![sweep]));
        let snapshot = flows.record(0).snapshot.unwrap();
        assert_eq!(snapshot.pending, Some(op::CALL));
        // The sale after the echo's await, its reply's page unpaid: no sale
        // counted.
        assert_eq!(snapshot.registers[8], u64::from(flows.method("sell").0));
        assert_eq!(flows.sales(), sales);
        flows.budget = defaults::REFINE_GAS;
        while !matches!(flows.record(0).state, WorkflowState::Ended(_)) {
            let sweep = flows.sweeping(1);
            results.push(flows.unmodelled(1, vec![sweep]));
            assert!(results.len() < 20, "it ends");
        }
        let total = u64::from(times * len);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(total.encode()));
        runs.push(results);
    }
    assert!(runs.windows(2).all(|pair| pair[0] == pair[1]));
}
