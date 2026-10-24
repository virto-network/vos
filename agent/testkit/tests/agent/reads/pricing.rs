//! What a read costs the agent beyond what its step is charged, and a read
//! whose kernel spends the step.

use super::*;

/// The gas the refine of `inputs` at `time` spends beyond its steps' gas,
/// which holds what they run and are charged: the agent's own work, less
/// what the charges cover of it. The node's state is left as it was.
fn unpaid(node: &Node, time: u64, inputs: Vec<Input>) -> i64 {
    let invocation = node.run_refine(&node.work(time, inputs), crate::common::OUTER_GAS);
    let output = invocation.output_bounded(cap::OUTPUT).unwrap();
    let (result, _) = vos_wire::result::split_output(&output).unwrap();
    let steps: u64 = result.steps.iter().map(|step| ran(step).gas_used).sum();
    invocation.gas_used as i64 - steps as i64
}

/// What the agent spends serving a read of a hundred and fifty rows beyond
/// what its step is charged, against the same read unserved: decoding and
/// checking the rows, copying them into the kernel's input, serving them
/// to it and keeping them in its attest, and its compressions' serving. It
/// leaves a fifth spare of what the agent accounts for them: `SERVED_BYTE`
/// a byte, `PRECOMPILE_SERVING` a compression.
#[test]
fn serving_a_read_pays_for_itself() {
    let entries: Vec<(u64, u64)> = (0..200).map(|key| (key, key)).collect();
    let mut reads = Reads::with(&entries);
    let keys: Vec<u64> = (0..150).collect();
    let id = reads.start(T0 + 10, "sum_at_cut", keys.clone());
    let (request, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read);
    let bytes = served.encode().len();
    let input = [keys.encode(), served.encode()].concat();
    let ran = run_kernel(&kernel("reader", "sum_entries"), &input, 1 << 32).unwrap();
    let at = |served: Option<&Served>| {
        unpaid(
            &reads.node,
            T0 + 20,
            vec![reads.resume(WINDOW, request, served)],
        )
    };
    let spent = at(Some(&served)) - at(None);
    let accounted =
        defaults::SERVED_BYTE * bytes as u64 + defaults::PRECOMPILE_SERVING * ran.compressions;
    println!(
        "a read of {} rows, {bytes} bytes and {} compressions served: the agent spends {spent} \
         beyond its charges, {:.1} a byte, of {accounted} accounted",
        keys.len(),
        ran.compressions,
        spent as f64 / bytes as f64,
    );
    assert!(
        spent <= (accounted * 4 / 5) as i64,
        "{spent} of {accounted}"
    );
}

/// What the agent spends checking a `Stating` kernel's statement parts,
/// their io-hash, for each block of its return, beyond what its caller is
/// charged: sixteen attests of 8 KiB against sixteen of none. It leaves a
/// fifth of the charge, `IO_HASH_BLOCK` a block, spare.
#[test]
fn checking_statement_parts_pays_for_itself() {
    let mut reads = Reads::with(&[(1, 1)]);
    let len = 8u32 << 10;
    // Neither refine applies: both requests are the session's next.
    let mut at = |len: u32| {
        let input = reads.request("attest_padded", (16u32, len));
        reads.sequence -= 1;
        unpaid(&reads.node, T0 + 10, vec![input])
    };
    let blocks = 16 * i64::from(len) / 128;
    let beyond = (at(len) - at(0)) / blocks;
    let cost = price::IO_HASH_BLOCK as i64 + beyond;
    println!(
        "a statement's parts checked: charged {} a block, costs the agent {cost}",
        price::IO_HASH_BLOCK
    );
    assert!(cost <= (price::IO_HASH_BLOCK * 4 / 5) as i64, "{cost}");
}

/// A read whose kernel spends the step's limit answers its workflow: run
/// out of gas, the step is preempted and the workflow resumes in the next
/// with the attest failed; run to its end leaving the step no gas, the step
/// is preempted with the statement recorded, and the workflow resumes with
/// its output.
#[test]
fn a_read_whose_kernel_spends_the_step_answers_its_workflow() {
    let mut reads = Reads::with(&[(1, 7)]);
    let limit = 2_000_000 - price::ATTEST;
    let kernel = kernel("reader", "spin");
    let id = reads.start(T0 + 10, "spin_at_cut", (1u64, 0u64));
    let (_, read) = reads.asked(WINDOW, id, 0);
    let served = reads.served(WINDOW, &read).encode();
    let runs = |rounds: u64| {
        let input = [(1u64, rounds).encode(), served.clone()].concat();
        run_kernel(&kernel, &input, limit).is_ok()
    };
    // The most rounds the kernel runs within the step's limit.
    let (mut low, mut high) = (0u64, 1 << 20);
    assert!(runs(low) && !runs(high));
    while high - low > 1 {
        let mid = (low + high) / 2;
        if runs(mid) { low = mid } else { high = mid }
    }
    for (at, (rounds, done)) in (T0 + 20..).step_by(20).zip([(high, false), (low, true)]) {
        let id = reads.start(at, "spin_at_cut", (1u64, rounds));
        let (request, read) = reads.asked(WINDOW, id, 0);
        let served = reads.served(WINDOW, &read);
        let resume = reads.resume(WINDOW, request, Some(&served));
        let result = reads.batch(at + 5, vec![resume]);
        assert_eq!(resumed(&result, request).attests.len(), usize::from(done));
        assert!(
            matches!(reads.record(id).state, WorkflowState::Preempted(_)),
            "{:?}",
            reads.record(id).state
        );
        let sweep = reads.node.sweep(at + 10);
        reads.batch(at + 10, vec![sweep]);
        let ended = ended(&reads.record(id)).clone();
        if done {
            let output = &resumed(&result, request).attests[0].output;
            assert_eq!(ended, Outcome::Done(output.clone()));
        } else {
            assert_eq!(ended, failed_with(AttestError::Failed));
        }
    }
}
