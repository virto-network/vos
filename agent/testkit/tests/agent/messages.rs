//! Messages from other agents: a request answered in the outbox whatever
//! its outcome, a reply consumed in its pair's order, and a message the
//! leader asserts failed in refine, each against the testkit.

use vos_testkit::{Step as KitStep, Testkit, decode};
use vos_wire::Encode;
use vos_wire::abi::{Failure, Refusal};
use vos_wire::batch::{Answer, Await, Body, Input, Message};
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::keys;
use vos_wire::result::{Outcome, Outgoing, Step};

use crate::common::{ALICE, COUNTER, LEDGER, Node, failed, ran, refused, setup};

/// The agent the messages come from.
const SENDER: AgentId = AgentId(9);

/// The await of request `counter` of workflow 3.
fn awaiting(counter: u64) -> Await {
    Await {
        workflow: WorkflowId(3),
        counter,
    }
}

fn call<A: Encode>(instance: InstanceId, method: MethodId, arguments: A, awaits: bool) -> Body {
    Body::Call {
        instance,
        method,
        arguments: arguments.encode(),
        awaiting: awaits.then(|| awaiting(1)),
    }
}

/// Each body from [`SENDER`], numbered in its pair from `first`.
fn messages(first: u64, bodies: &[Body]) -> Vec<Input> {
    bodies
        .iter()
        .zip(first..)
        .map(|(body, sequence)| {
            Input::Message(Message {
                from: SENDER,
                sequence,
                body: body.clone(),
            })
        })
        .collect()
}

/// Messages from [`SENDER`] the leader asserts failed, numbered in its
/// pair from `first`, each with the await it names, if any.
fn failures(first: u64, awaits: &[Option<Await>]) -> Vec<Input> {
    awaits
        .iter()
        .zip(first..)
        .map(|(awaiting, sequence)| Input::Failed {
            from: SENDER,
            sequence,
            awaiting: *awaiting,
        })
        .collect()
}

fn reply(counter: u64, answer: Answer) -> Outgoing {
    Outgoing {
        to: SENDER,
        body: Body::Reply {
            awaiting: awaiting(counter),
            answer,
        },
    }
}

/// The node's steps agree with the testkit's, each made by `expected`.
fn agrees(kit: &mut Testkit, steps: &[Step], expected: impl Fn(&mut Testkit, usize) -> KitStep) {
    kit.batch(1, [0; 32]);
    for (index, step) in steps.iter().enumerate() {
        let expected = expected(kit, index);
        let run = ran(step);
        assert_eq!(run.outcome, expected.outcome);
        assert_eq!(run.writes, expected.writes);
        assert_eq!(run.messages, expected.messages);
        assert_eq!(run.instances, expected.instances);
        assert_eq!(run.gas_used, expected.gas_used);
    }
}

/// The outbox entry for [`SENDER`] at `sequence`.
fn outbox(node: &Node, sequence: u64) -> Option<Outgoing> {
    node.get(&keys::outbox(SENDER, sequence))
        .map(|bytes| decode(&bytes).expect("an outgoing message"))
}

fn pair_mark(node: &Node) -> Option<u64> {
    node.value(&keys::pair_in(SENDER))
}

/// A request is answered on the reverse pair whatever its outcome: done,
/// the handler's failure, or refused before it ran, by role or by a method
/// it does not have. Its reply follows the step's own sends; a call that
/// does not await is answered nothing.
#[test]
fn a_request_is_answered_in_the_outbox_whatever_its_outcome() {
    let (actors, mut node, mut kit, _) = setup();
    let increment = actors.method(COUNTER, "increment");
    let bodies = [
        call(COUNTER, increment, 5u64, true),
        call(COUNTER, increment, u64::MAX, true),
        call(LEDGER, actors.method(LEDGER, "mint"), (1u64, 10u64), true),
        call(COUNTER, MethodId(999), (), true),
        call(COUNTER, actors.method(COUNTER, "spam"), 2u32, true),
        call(COUNTER, increment, 1u64, false),
    ];
    let result = node.batch(1, messages(1, &bodies));
    let answers = [
        Answer::Done(5u64.encode()),
        Answer::Failed {
            code: Failure::Handler,
            detail: vec![0],
        },
        Answer::Failed {
            code: Failure::Forbidden,
            detail: vec![],
        },
        Answer::Failed {
            code: Failure::Unknown,
            detail: vec![],
        },
        Answer::Done(2u32.encode()),
    ];
    for (index, answer) in answers.into_iter().enumerate() {
        let messages = &ran(&result.steps[index]).messages;
        assert_eq!(messages.last(), Some(&reply(1, answer)), "step {index}");
    }
    assert_eq!(failed(&result.steps[1]), Failure::Handler);
    assert!(ran(&result.steps[1]).writes.is_empty());
    let spam = &ran(&result.steps[4]).messages;
    assert_eq!(spam.len(), 3, "the step's two sends, then the reply");
    assert!(
        ran(&result.steps[5]).messages.is_empty(),
        "a call that does not await"
    );
    agrees(&mut kit, &result.steps, |kit, index| {
        kit.message(SENDER, &bodies[index])
    });

    // Sequenced on the reverse pair, as any message the agent sends.
    for sequence in 1..=5 {
        let body = outbox(&node, sequence).expect("a reply in the outbox").body;
        assert!(matches!(body, Body::Reply { .. }), "{body:?}");
    }
    assert_eq!(outbox(&node, 6), None);
    assert_eq!(node.value::<u64>(&keys::pair_out(SENDER)), Some(5));
    assert_eq!(pair_mark(&node), Some(6));
    assert_eq!(
        node.query(ALICE, COUNTER, actors.method(COUNTER, "value"), ().encode()),
        Outcome::Done(6u64.encode()),
        "the requests that ran"
    );
}

/// A reply is consumed in its pair's order, with nothing to resume: the
/// pair's mark advances, so the leader acknowledges it, and nothing else
/// changes. A second copy is refused at the mark.
#[test]
fn a_reply_is_consumed_in_its_pairs_order() {
    let (_, mut node, mut kit, _) = setup();
    let bodies = [
        Body::Reply {
            awaiting: awaiting(1),
            answer: Answer::Done(vec![1]),
        },
        Body::Reply {
            awaiting: awaiting(2),
            answer: Answer::Started(WorkflowId(8)),
        },
    ];
    // Every row but the pair's mark and the agent's own records.
    let rows = |node: &Node| -> Vec<Vec<u8>> {
        let own = [keys::pair_in(SENDER), keys::version(), keys::batch_time()];
        node.state
            .keys()
            .filter(|key| !own.contains(key))
            .cloned()
            .collect()
    };
    let before = rows(&node);
    let result = node.batch(1, messages(1, &bodies));
    for step in &result.steps {
        let run = ran(step);
        assert_eq!(run.outcome, Outcome::Done(vec![]));
        assert!(run.writes.is_empty() && run.messages.is_empty() && run.instances.is_empty());
    }
    agrees(&mut kit, &result.steps, |kit, index| {
        kit.message(SENDER, &bodies[index])
    });
    assert_eq!(pair_mark(&node), Some(2));
    assert_eq!(rows(&node), before, "nothing else changed");

    let again = node.batch(2, messages(2, &bodies[1..]));
    assert_eq!(refused(&again.steps[0]), Refusal::Sequence);
    assert_eq!(pair_mark(&node), Some(2));
}

/// A message the leader asserts failed in refine never runs, and is
/// consumed in its pair's order as a failed step: answered when it
/// awaits, its pair's mark advanced either way. Out of order, it is
/// refused as any message is.
#[test]
fn a_message_failed_in_refine_is_consumed_and_answered() {
    let (actors, mut node, mut kit, _) = setup();
    let awaits = [Some(awaiting(1)), None];
    let result = node.batch(1, failures(5, &awaits[..1]));
    assert_eq!(refused(&result.steps[0]), Refusal::Sequence);
    assert_eq!(pair_mark(&node), None);

    let result = node.batch(2, failures(1, &awaits));
    for step in &result.steps {
        assert_eq!(failed(step), Failure::InRefine);
        let run = ran(step);
        assert!(run.writes.is_empty() && run.instances.is_empty());
        assert_eq!(run.gas_used, 0);
    }
    let in_refine = Answer::Failed {
        code: Failure::InRefine,
        detail: vec![],
    };
    assert_eq!(ran(&result.steps[0]).messages, [reply(1, in_refine)]);
    assert!(ran(&result.steps[1]).messages.is_empty());
    agrees(&mut kit, &result.steps, |kit, index| {
        kit.failed(SENDER, awaits[index])
    });
    assert_eq!(pair_mark(&node), Some(2));
    assert!(matches!(
        outbox(&node, 1).map(|outgoing| outgoing.body),
        Some(Body::Reply { .. })
    ));
    assert_eq!(
        node.query(ALICE, COUNTER, actors.method(COUNTER, "value"), ().encode()),
        Outcome::Done(0u64.encode()),
        "nothing ran"
    );
}
