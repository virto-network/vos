//! Every host alike: the interpreter and the recompiler, and a VOS host and
//! a JAM host, agree on every byte of a scenario's batches.

use super::*;

/// A batch as a scenario ran it: its refine's output, the gas the refine
/// used, and the state after it.
type Ran = (Vec<u8>, u64, BTreeMap<Vec<u8>, Vec<u8>>);

/// A scenario of workflows that await, compute and write their memory
/// back, and are preempted: at the start of a block, at a call of this
/// agent's once their share is spent, at a first effect a tight batch
/// cannot cover, and at a page it cannot pay. Run on `node`, batch by
/// batch.
fn scenario(node: Node) -> Vec<Ran> {
    let mut flows = Flows::new(node);
    let mut batches = Vec::new();
    let mut run = |flows: &mut Flows, budget: u64, inputs: Vec<Input>| {
        flows.time += 1;
        let work = flows
            .node
            .budgeted_work(flows.time, [0; 32], budget, inputs);
        let invocation = flows.node.run_refine(&work, crate::common::OUTER_GAS);
        assert_eq!(invocation.exit, vos_pvm::ExitReason::Halt, "refine halts");
        let output = invocation.output_bounded(cap::OUTPUT).unwrap();
        flows.node.accumulate(&output);
        flows.node.version += 1;
        let result = split_output(&output).unwrap().0;
        batches.push((output, invocation.gas_used, flows.node.state.clone()));
        result
    };
    let budget = defaults::REFINE_GAS;
    let starts = vec![
        flows.start("transfer", transfer(0)),
        flows.start("compute", (16_384u32, 2u32)),
        flows.start("scratch", RISK.0),
    ];
    run(&mut flows, budget, starts);
    let answers = vec![
        flows.reply(RISK, 0, 0, Answer::Done(1u64.encode())),
        flows.reply(RISK, 2, 0, Answer::Done(1u64.encode())),
    ];
    run(&mut flows, budget, answers);
    for _ in 0..3 {
        let sweep = flows.node.sweep(flows.time + 1);
        run(&mut flows, budget, vec![sweep]);
    }
    let answer = flows.reply(RISK, 2, 1, Answer::Done(1u64.encode()));
    run(&mut flows, budget, vec![answer]);

    // Preempted: at blocks' starts, at calls once the share is spent, at a
    // first effect a tight batch cannot cover, and at pages one cannot pay.
    let starts = vec![
        flows.start("grind", (4096u32, 200u32)),
        flows.start("relay", relayed(2)),
    ];
    run(&mut flows, budget, starts);
    let start = flows.start("settle", settle_rounds());
    run(&mut flows, SETTLE_LIMIT + SETTLE_LIMIT / 2, vec![start]);
    let pending = flows.record(5).snapshot.unwrap().pending;
    assert_eq!(pending, Some(Op::Call.id()));
    // Some 200 pages held, restored a step, and room for 25 more.
    let start = flows.start("grind", (100_000u32, 1u32));
    let tight = defaults::WORKFLOW_RESERVE
        + 1100 * defaults::ARM_PAGE
        + 200 * defaults::RESTORED_PAGE
        + GRIND_LIMIT
        + defaults::FINISH_RESERVE
        + defaults::SWEEP_RESERVE
        + 25 * defaults::WRITTEN_PAGE;
    run(&mut flows, tight, vec![start]);
    let (first, last) = (3, 6);
    let limit = flows.record(last).gas;
    assert_eq!(limit, GRIND_LIMIT);
    let mut short = 0;
    for _ in 0..40 {
        if (first..=last).all(|id| matches!(flows.record(id).state, WorkflowState::Ended(_))) {
            break;
        }
        let sweep = flows.node.sweep(flows.time + 1);
        let result = run(&mut flows, tight, vec![sweep]);
        let stepped = result.steps.iter().any(|step| {
            matches!(step, Step::Ran(run) if run.input == InputRef::Due { workflow: WorkflowId(last) }
                && run.gas_used < limit)
        });
        if stepped && matches!(flows.record(last).state, WorkflowState::Preempted(_)) {
            short += 1;
        }
    }
    assert!(short > 0, "preempted at a page it could not pay");
    for workflow in 0..=last {
        let record = flows.record(workflow);
        let outcome = ended(&record);
        assert!(
            matches!(outcome, Outcome::Done(_)),
            "{workflow}: {outcome:?}"
        );
    }
    let stored: usize = batches
        .iter()
        .map(|(output, ..)| split_output(output).unwrap().1.len())
        .sum();
    assert!(stored > 16, "{stored} pages compared");
    batches
}

/// The interpreter and the recompiler agree on every byte of every batch:
/// each step's gas and snapshot, and the pages that ride beside the work
/// result.
#[test]
fn the_interpreter_and_the_recompiler_agree() {
    let runs: Vec<_> = Node::backends()
        .into_iter()
        .map(Node::on)
        .map(scenario)
        .collect();
    for other in &runs[1..] {
        assert_eq!(other.len(), runs[0].len());
        for (index, ((output, ..), (expected, ..))) in other.iter().zip(&runs[0]).enumerate() {
            assert!(output == expected, "batch {index} differs");
        }
    }
}

/// A VOS host and a JAM host, which reads applied state as JAM mode's
/// witnesses will give it, agree on every byte of every workflow batch and
/// on the state after it, though the JAM host's agent hashes the pages in
/// software, at an outer gas of its own.
#[test]
fn vos_and_jam_hosts_agree_on_workflow_batches() {
    let vos = scenario(Node::new());
    let jam = scenario(Node::jam(true));
    assert_eq!(vos.len(), jam.len());
    for (index, ((on_vos, vos_gas, vos_state), (on_jam, jam_gas, jam_state))) in
        vos.iter().zip(&jam).enumerate()
    {
        assert!(on_vos == on_jam, "batch {index} differs");
        assert!(vos_state == jam_state, "the state after batch {index}");
        assert_ne!(vos_gas, jam_gas, "batch {index}: the outer gas differs");
    }
}
