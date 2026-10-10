//! Accumulate: apply work results to the agent's storage, in order.
//!
//! Each step that ran writes its writes, advances its session or pair mark,
//! keeps its reply in the session's window and queues its messages in the
//! outbox with their pair sequences; an acknowledgement clears the outbox
//! through its sequence. A step's new session is created first. A refused
//! step applies nothing. A work result built on another state version,
//! timed before the agent's latest, or holding a new session whose creation
//! time is far from its own, applies nothing at all: refine refuses such a
//! session, so the result was not refined on this state as it says.

use vos_wire::ids::{SessionId, SessionRef};
use vos_wire::jam::AccumulateInput;
use vos_wire::records::{SessionMark, stored, unstored};
use vos_wire::result::{InputRef, Run, Step, WorkResult};
use vos_wire::{Decode, Encode, defaults, keys};

use crate::host::{fetch_input, read, write};

pub fn run(arguments: &[u8]) {
    let (_, used) = vos_pvm_program::read_nat(arguments, 0).expect("the timeslot");
    let (_, more) = vos_pvm_program::read_nat(arguments, used).expect("the service");
    let (count, _) = vos_pvm_program::read_nat(arguments, used + more).expect("the input count");
    for index in 0..count {
        let Some(bytes) = fetch_input(index) else {
            continue;
        };
        let Some(AccumulateInput::Operand(operand)) = AccumulateInput::decode(&bytes) else {
            continue;
        };
        let Ok(output) = operand.result else {
            continue;
        };
        if let Ok((result, _)) = WorkResult::decode(&output) {
            apply(&result);
        }
    }
}

fn get<T: Decode>(key: &[u8]) -> Option<T> {
    let bytes = read(key)?;
    let value = unstored(&bytes)?;
    T::decode(value).ok().map(|(value, _)| value)
}

fn put(key: &[u8], value: &[u8]) {
    write(key, &stored(value));
}

fn delete(key: &[u8]) {
    write(key, &[]);
}

/// A step's session, created when the step is its first.
fn session(named: &SessionRef) -> SessionId {
    let session = match named {
        SessionRef::Known(id) => return *id,
        SessionRef::New(session) => session,
    };
    // An earlier step of the same result may have created it.
    if let Some(id) = get::<SessionId>(&keys::session_index(&session)) {
        return id;
    }
    let id = SessionId(get::<u64>(&keys::next_session()).unwrap_or(0));
    put(&keys::next_session(), &(id.0 + 1).encode());
    put(&keys::session_index(&session), &id.encode());
    put(&keys::session_of(id), &session.encode());
    let live = get::<u64>(&keys::live_sessions()).unwrap_or(0);
    put(&keys::live_sessions(), &(live + 1).encode());
    id
}

/// Whether a step of `result` creates a session far from its time.
fn stale(result: &WorkResult) -> bool {
    result.steps.iter().any(|step| match step {
        Step::Ran(Run {
            input:
                InputRef::Request {
                    session: SessionRef::New(session),
                    ..
                },
            ..
        }) => session.t0.abs_diff(result.time) > defaults::SESSION_SKEW_MS,
        _ => false,
    })
}

fn apply(result: &WorkResult) {
    let version: u64 = get(&keys::version()).unwrap_or(0);
    if result.version != version {
        return;
    }
    let latest: u64 = get(&keys::batch_time()).unwrap_or(0);
    if result.time < latest || stale(result) {
        return;
    }
    if result.time > latest {
        put(&keys::batch_time(), &result.time.encode());
    }
    for step in &result.steps {
        if let Step::Ran(run) = step {
            apply_run(run, result.time);
        }
    }
    put(&keys::version(), &(version + 1).encode());
}

fn apply_run(run: &Run, time: u64) {
    let session = match &run.input {
        InputRef::Request { session: named, .. } => Some(session(named)),
        _ => None,
    };
    for item in &run.writes {
        match &item.value {
            Some(value) => put(&item.key, value),
            None => delete(&item.key),
        }
    }
    match run.input {
        InputRef::Request { sequence, .. } => {
            let id = session.expect("a request's session");
            let mark = SessionMark { sequence, time };
            put(&keys::session(id), &mark.encode());
            put(&keys::reply(id, sequence), &run.outcome.encode());
            if let Some(old) = sequence.checked_sub(defaults::REPLY_WINDOW) {
                delete(&keys::reply(id, old));
            }
        }
        InputRef::Message { from, sequence } => {
            put(&keys::pair_in(from), &sequence.encode());
        }
        InputRef::Admin => {}
        InputRef::Ack { to, sequence } => {
            // Monotonic and idempotent: a stale ack does nothing, one past
            // what was sent stops there, and one ack clears at most
            // `ACK_LIMIT` entries; the node acks again for the rest.
            let acked = get::<u64>(&keys::acked(to)).unwrap_or(0);
            let sent = get::<u64>(&keys::pair_out(to)).unwrap_or(0);
            let through = sequence
                .min(sent)
                .min(acked.saturating_add(defaults::ACK_LIMIT));
            for cleared in acked + 1..=through {
                delete(&keys::outbox(to, cleared));
            }
            if through > acked {
                put(&keys::acked(to), &through.encode());
            }
        }
    }
    for message in &run.messages {
        let next = get::<u64>(&keys::pair_out(message.to)).unwrap_or(0) + 1;
        put(&keys::outbox(message.to, next), &message.encode());
        put(&keys::pair_out(message.to), &next.encode());
    }
}
