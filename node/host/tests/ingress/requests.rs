//! Requests through the node API: batches that sweep, unread and
//! duplicate answers, and a request resent with its sequence.

use super::*;

/// A batch whose time makes the first expiry row due sweeps first: an
/// expired session is gone once the next call is answered.
#[test]
fn a_busy_leader_sweeps_in_its_batches() {
    let served = Served::plain();
    let start = served.at_bucket_start();
    let mut first = served.client(1);
    let mut second = served.client(2);
    assert_eq!(done(served.call(&mut first, 1)), 1);
    assert_eq!(done(served.call(&mut second, 1)), 2);
    let held = first.session(served.agent);
    served
        .clock
        .store(expiry::due(expiry::bucket(start)) - 1, Ordering::SeqCst);
    assert_eq!(done(served.call(&mut second, 1)), 3);
    assert!(served.holds(&held), "not due yet");
    served
        .clock
        .store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    assert_eq!(done(served.call(&mut second, 1)), 4);
    assert!(!served.holds(&held));
}

/// Calls sent on one connection, their answers never read, the connection
/// then dropped: their replies come from the window. Each goes once the
/// one before applied, since frames on a connection run at once, in no
/// order a session's sequence would take.
#[test]
fn unread_answers_come_back_from_the_window() {
    let served = Served::plain();
    let client = served.client(1);
    let mut stream = super::api::connect(&served.socket);
    for (sequence, by, total) in [(1u64, 1u64, 1u64), (2, 2, 3), (3, 3, 6)] {
        let body = client
            .call_body(
                served.agent,
                sequence,
                COUNTER,
                served.increment,
                &by.encode(),
            )
            .unwrap();
        super::api::send(
            &mut stream,
            vos_api::Kind::Call as u16,
            sequence,
            &[served.agent.encode(), body].concat(),
        );
        wait_until("the call applies", || served.value(&client) == total);
    }
    drop(stream);
    let replies: Vec<u64> = [(1u64, 1u64), (2, 2), (3, 3)]
        .into_iter()
        .map(|(sequence, by)| done(served.increment(&client, sequence, by)))
        .collect();
    assert_eq!(replies, [1, 3, 6], "each reply from the window");
    assert_eq!(served.value(&client), 6);
}

#[test]
fn a_duplicate_in_flight_waits_for_its_answer() {
    let gate = Arc::new(Gate::default());
    let served = Arc::new(Served::start(gate.clone()));
    let client = Arc::new(served.client(1));
    let closed = gate.close();
    let reached = gate.reached();
    let first = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    wait_until("the first is in flight", || gate.reached() > reached);
    let second = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    wait_until("the second waits on the first", || {
        served.node.calls_in_flight() == 2 || second.is_finished()
    });
    drop(closed);
    assert_eq!(done(first.join().unwrap()), 5);
    assert_eq!(done(second.join().unwrap()), 5);
    assert_eq!(served.value(&client), 5, "applied once");
}

/// Holds the refine of a batch holding an input, a request or a message,
/// that calls with the poisoned arguments at its gate, then fails it,
/// once; and holds commits at theirs.
#[derive(Default)]
struct GatedPoison {
    poison: Vec<u8>,
    armed: AtomicBool,
    refines: Gate,
    commits: Gate,
}

impl Hooks for GatedPoison {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        if !carries(batch, &self.poison) || !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        self.refines.pass();
        self.armed.swap(false, Ordering::SeqCst)
    }

    fn before_commit(&self) {
        self.commits.pass();
    }
}

/// A request the agent program fails alone is not consumed: the requests
/// queued behind it are gaps, and the client resends from it, even while
/// they are still in flight.
#[test]
fn a_request_not_consumed_is_resent_with_its_sequence() {
    let gate = Arc::new(GatedPoison {
        poison: 1u64.encode(),
        ..GatedPoison::default()
    });
    let served = Arc::new(Served::start(gate.clone()));
    let client = Arc::new(served.client(1));
    let refines = gate.refines.close();
    gate.armed.store(true, Ordering::SeqCst);
    let send = |sequence: u64| {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, sequence, sequence))
    };
    // Queued, or answered at once: then its answer fails the test, rather
    // than the wait.
    let queued = |calls, sent: &std::thread::JoinHandle<Response>| {
        wait_until(&format!("{calls} calls queued"), || {
            served.node.calls_in_flight() == calls || sent.is_finished()
        })
    };
    let first = send(1);
    wait_until("the first is refined", || gate.refines.reached() > 0);
    let second = send(2);
    queued(2, &second);
    let third = send(3);
    queued(3, &third);
    // The batch of 2 and 3 will wait at its commit, so they stay in flight.
    let commits = gate.commits.close();
    let reached = gate.commits.reached();
    drop(refines);
    assert_eq!(first.join().unwrap(), Response::NotConsumed);
    wait_until("2 and 3 reach their commit", || {
        gate.commits.reached() > reached
    });
    // Resent while 2 and 3 are in flight: the lane went back to before 1.
    let resent = send(1);
    queued(3, &resent);
    drop(commits);
    assert_eq!(second.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(third.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(done(resent.join().unwrap()), 1);
    let rest: Vec<u64> = (2..=3)
        .map(|sequence| done(served.increment(&client, sequence, sequence)))
        .collect();
    assert_eq!(rest, [3, 6]);
}
