//! Requests through the ingress: batches that sweep, pipelined and
//! duplicate requests, a request resent with its sequence, and bodies the
//! ingress refuses.

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

#[test]
fn pipelined_requests_recover_their_lost_replies() {
    let served = Served::plain();
    let client = served.client(1);
    let address: SocketAddr = served.base.trim_start_matches("http://").parse().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    for (sequence, by) in [(1u64, 1u64), (2, 2), (3, 3)] {
        let body = client
            .call_body(
                served.agent,
                sequence,
                COUNTER,
                served.increment,
                &by.encode(),
            )
            .unwrap();
        let head = format!(
            "POST /agents/{}/calls HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
            served.agent.0,
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
    }
    wait_until("all three apply", || served.value(&client) == 6);
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
    std::thread::sleep(Duration::from_millis(100));
    drop(closed);
    assert_eq!(done(first.join().unwrap()), 5);
    assert_eq!(done(second.join().unwrap()), 5);
    assert_eq!(served.value(&client), 5, "applied once");
}

/// Holds the refine of a batch holding the poisoned arguments at its
/// gate, then fails it, once; and holds commits at theirs.
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
    let first = send(1);
    wait_until("the first is refined", || gate.refines.reached() > 0);
    let second = send(2);
    std::thread::sleep(Duration::from_millis(100));
    let third = send(3);
    std::thread::sleep(Duration::from_millis(100));
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
    std::thread::sleep(Duration::from_millis(100));
    drop(commits);
    assert_eq!(second.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(third.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(done(resent.join().unwrap()), 1);
    let rest: Vec<u64> = (2..=3)
        .map(|sequence| done(served.increment(&client, sequence, sequence)))
        .collect();
    assert_eq!(rest, [3, 6]);
}

#[test]
fn bodies_past_the_limit_or_without_a_length_are_refused_with_a_reason() {
    let served = Served::plain();
    let calls = format!("/agents/{}/calls", served.agent.0);
    let large = format!("POST {calls} HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n");
    assert_eq!(
        status_line(&served.base, large.as_bytes()),
        "HTTP/1.1 413 Content Too Large"
    );
    let chunked = format!("POST {calls} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(
        status_line(&served.base, chunked.as_bytes()),
        "HTTP/1.1 411 Length Required"
    );
}
