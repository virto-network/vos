//! Sections: a workflow reaches its instance's state, its tables included,
//! in synchronous sections, as the instance itself. A section is an effect,
//! so it never spans a pause, and inside one the agent serves only the
//! instance's rows, the time and logs. Every step the model's.

use super::*;

/// The shop's sales and an order's amount, `record`'s result.
type Recorded = (u64, Option<u64>);

fn trapped() -> Outcome {
    Outcome::Failed {
        code: Failure::Trapped,
        detail: vec![],
    }
}

/// An update writes the instance's struct and a table row in one section,
/// which the next section of the same unit reads back; what a handler
/// changes between a workflow's pauses, its next section reads afresh.
#[test]
fn sections_read_and_write_the_instances_state() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("record", (7u64, 30u64));
        let result = flows.batch(1, vec![start]);
        let recorded: Recorded = (30, Some(30));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(recorded.encode()));
        assert!(
            due(&result, 0).writes.len() >= 2,
            "the struct and the order's row"
        );
        assert_eq!(flows.sales(), 30);

        let start = flows.start("restock", vec![5u64, 6]);
        let result = flows.batch(1, vec![start]);
        assert_eq!(due(&result, 1).outcome, Outcome::Done(vec![]));
        assert_eq!(
            flows.sales(),
            35,
            "the first section committed with its step"
        );
        let sell = flows.method("sell");
        let sold = flows.sessions.request(ALICE, SHOP, sell, 100u64);
        flows.batch(1, vec![sold]);
        flows.sweep(1);
        flows.sweep(1);
        assert_eq!(
            ended(&flows.record(1)),
            &Outcome::Done(vec![35u64, 141].encode()),
            "the second section read the sale made while it slept"
        );
        assert_eq!(flows.sales(), 141);
    }
}

/// From its first section a unit runs to its next await within the step's
/// limit, never preempted: what it writes still holds what it read. Past
/// the limit the step fails whole, its read and its write discarded,
/// where a unit with no effect yet would have been preempted.
#[test]
fn a_unit_with_a_section_is_never_preempted() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let sell = flows.method("sell");
        let sold = flows.sessions.request(ALICE, SHOP, sell, 10u64);
        let start = flows.start("bump", (5u64, 1_000u32));
        let result = flows.batch(1, vec![sold, start]);
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(15u64.encode()));

        // Its reads of the time alone pass its limit of 5M.
        let start = flows.start("bump", (5u64, 3_000u32));
        let result = flows.batch(1, vec![start]);
        let out_of_gas = Outcome::Failed {
            code: Failure::OutOfGas,
            detail: vec![],
        };
        assert_eq!(due(&result, 1).outcome, out_of_gas);
        assert!(
            due(&result, 1)
                .writes
                .iter()
                .all(|write| { !write.key.starts_with(&keys::instance_prefix(SHOP)) })
        );
        assert_eq!(
            ended(&flows.record(1)),
            &out_of_gas,
            "failed, not preempted"
        );
        assert_eq!(flows.sales(), 15);
    }
}

/// Inside a section the agent serves only the instance's rows, the time,
/// logs and the close: a call, a send, a request, a wait for a result, a
/// sleep, a second open or the input fails the step. So does an open of
/// another instance, a row operation or a close with none open, and an
/// end with one open. A section never spans a pause.
#[test]
fn a_section_refuses_what_is_not_its_instances_state() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let starts: Vec<Input> = (0..=10u8).map(|how| flows.start("misuse", how)).collect();
        let result = flows.batch(1, starts);
        for how in 0..=10u64 {
            let run = due(&result, how);
            assert_eq!(run.outcome, trapped(), "misuse {how}");
            assert!(run.messages.is_empty(), "misuse {how}: nothing sent");
            assert_eq!(ended(&flows.record(how)), &trapped(), "misuse {how}");
        }
        assert_eq!(flows.sales(), 0);
    }
}
