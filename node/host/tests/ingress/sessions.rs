//! Client-named sessions: calls in their sequences, signatures and
//! staleness checked, expiry, and an answer lost.

use super::*;

#[test]
fn calls_follow_their_session_sequence() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    assert_eq!(done(served.increment(&client, 1, 5)), 5);
    assert_eq!(
        done(served.increment(&client, 1, 5)),
        5,
        "a duplicate, from the window"
    );
    assert_eq!(served.value(&client), 5, "applied once");
    assert_eq!(
        served.increment(&client, 3, 1),
        Response::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 0, 1),
        Response::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 2 + defaults::REPLY_WINDOW, 1),
        Response::Rejected(Rejection::Ahead)
    );
    for sequence in 2..=defaults::REPLY_WINDOW + 1 {
        done(served.increment(&client, sequence, 1));
    }
    assert_eq!(
        served.increment(&client, 1, 5),
        Response::Rejected(Rejection::TooOld)
    );
    assert_eq!(
        done(served.increment(&client, 2, 1)),
        6,
        "the oldest reply kept"
    );
    // Sequences are per (session, agent): another session starts at 1.
    let other = served.client(2);
    assert_eq!(done(served.increment(&other, 1, 1)), 70);
}

#[test]
fn signatures_sessions_and_staleness_are_checked() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    let agent = served.agent;
    let path = format!("/agents/{}/calls", agent.0);

    let mut body = client
        .call_body(agent, 1, COUNTER, served.increment, &5u64.encode())
        .unwrap();
    let (mut call, _) = Call::decode(&body).unwrap();
    call.arguments = 6u64.encode();
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature),
        "arguments changed after signing"
    );
    // The session is in the signed bytes, and its key signs.
    call = Call::decode(&body).unwrap().0;
    call.session.name[0] ^= 1;
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    call = Call::decode(&body).unwrap().0;
    call.session.key = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    // Signed for one agent, sent to another: the agent's identity is in
    // the signed bytes.
    let operator = Operator::new(&served.target, &served.token);
    let Ok(Response::Created(other)) = operator.create_agent(Vec::new()) else {
        panic!("another agent")
    };
    let elsewhere = format!("/agents/{}/calls", other.0);
    assert_eq!(
        served.post(&elsewhere, &body),
        Response::Rejected(Rejection::BadSignature)
    );
    assert_eq!(
        served.post(&format!("/agents/{}/calls", other.0 + 1), &body),
        Response::NoAgent
    );
    body.truncate(body.len() - 1);
    assert_eq!(
        served.post(&path, &body),
        Response::Rejected(Rejection::Malformed)
    );

    // A new session must start near the agent's time, which the refusal
    // gives.
    let stale = |t0: u64| {
        let mut call = Call::decode(
            &client
                .call_body(agent, 1, COUNTER, served.increment, &1u64.encode())
                .unwrap(),
        )
        .unwrap()
        .0;
        call.session.t0 = t0;
        let key = SigningKey::from_bytes(&[1; 32]);
        let identity = client.identity(agent).unwrap();
        let message = vos_wire::ingress::call_message(
            &identity,
            &call.session,
            call.sequence,
            call.instance,
            call.method,
            &call.arguments,
        );
        call.signature = ed25519_dalek::Signer::sign(&key, &message).to_bytes();
        served.post(&path, &call.encode())
    };
    let now = served.now();
    for t0 in [
        now - defaults::SESSION_SKEW_MS - 1,
        now + defaults::SESSION_SKEW_MS + 1,
    ] {
        assert_eq!(
            stale(t0),
            Response::Rejected(Rejection::StaleSession { now })
        );
    }
    assert_eq!(done(stale(now - defaults::SESSION_SKEW_MS + 1_000)), 1);

    // A query's `not_after` is by the client's clock, moved to the node's
    // time as the client last learned it, and again once refused.
    let now = served.now();
    let query = |not_after| {
        client
            .query(agent, COUNTER, served.value, &[], not_after)
            .unwrap()
    };
    let wall = vos_node::wall_clock();
    assert_eq!(
        query(wall - 3_600_000),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    assert_eq!(
        query(vos_node::wall_clock() + 600_000),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    assert_eq!(done(query(vos_node::wall_clock() + 1_000)), 1);
    // The node's clock ten minutes ahead: refused once, the query goes
    // again at its time.
    served.clock.store(now + 600_000, Ordering::SeqCst);
    assert_eq!(done(query(vos_node::wall_clock() + 60_000)), 1);
}

/// An expired session is refused for good: the client starts another,
/// and when its clock is off the agent's, starts it again at the time the
/// refusal gives.
#[test]
fn an_expired_session_is_refused_and_the_client_starts_another() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let mut client = served.client(1);
    assert_eq!(done(served.call(&mut client, 5)), 5);
    let first = client.session(served.agent);
    served
        .clock
        .fetch_add(defaults::SESSION_EXPIRY_MS + 1, Ordering::SeqCst);
    assert_eq!(
        served.increment(&client, 2, 1),
        Response::Refused(Refusal::Expired)
    );
    assert_eq!(done(served.call(&mut client, 1)), 6);
    let renewed = client.session(served.agent);
    assert_ne!(renewed, first);
    assert!(
        renewed.t0.abs_diff(served.now()) <= defaults::SESSION_SKEW_MS,
        "started at the agent's time"
    );
    assert_eq!(client.sessions()[&served.agent].next, 2);
}

/// A call whose answer was lost goes again with its sequence, answered
/// from the window while the agent holds its session, expired or not.
/// Once the session is collected nothing can say whether it ran: the
/// client says so, and never runs it again. A first call in a session
/// never created goes again in a new session once no leader can create
/// the old one, and is lost past the time the old one could have been
/// collected.
#[test]
fn a_call_whose_answer_was_lost_is_answered_once_or_lost() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let start = served.at_bucket_start();
    let mut client = served.client(1);
    assert_eq!(done(served.call(&mut client, 1)), 1);
    // The second call runs, and its answer is lost.
    let before = client.sessions();
    assert_eq!(done(served.call(&mut client, 2)), 3);
    let kept = before[&served.agent];
    let session = Session {
        key: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        name: kept.name,
        t0: kept.t0,
    };
    let again = |kept: client::Kept| {
        let sessions = HashMap::from([(served.agent, kept)]);
        let mut client = Client::resume(
            &served.target,
            SigningKey::from_bytes(&[1; 32]),
            sessions,
            HashMap::new(),
        );
        client.repeats_unknown(served.agent);
        client.call(served.agent, COUNTER, served.increment, &2u64.encode())
    };

    served
        .clock
        .store(start + defaults::SESSION_EXPIRY_MS + 1, Ordering::SeqCst);
    assert!(served.now() < expiry::due(expiry::bucket(start)));
    assert_eq!(done(again(kept).unwrap()), 3, "from the window");
    assert_eq!(served.value(&client), 3);

    served
        .clock
        .store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    wait_until("the idle leader collects the session", || {
        !served.holds(&session)
    });
    assert!(matches!(again(kept), Err(ClientError::Lost)));
    assert_eq!(served.value(&client), 3, "and it did not run again");

    // A session whose first call reached no leader.
    let now = served.now();
    let never = client::Kept {
        name: [7; 16],
        t0: now,
        next: 1,
    };
    served
        .clock
        .store(now + 2 * defaults::SESSION_SKEW_MS, Ordering::SeqCst);
    assert_eq!(
        again(never).unwrap(),
        Response::TimedOut,
        "a leader could still create it"
    );
    served
        .clock
        .store(now + 2 * defaults::SESSION_SKEW_MS + 1, Ordering::SeqCst);
    assert_eq!(done(again(never).unwrap()), 5, "in a new session, once");
    let old = client::Kept {
        name: [8; 16],
        t0: served.now() - defaults::SESSION_EXPIRY_MS,
        next: 1,
    };
    assert!(matches!(again(old), Err(ClientError::Lost)));
    assert_eq!(served.value(&client), 5);
}
