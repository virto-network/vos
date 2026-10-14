//! Accumulate: apply work results to the agent's storage, in order.
//!
//! Each step that ran writes its writes, advances its session or pair mark,
//! keeps its reply in the session's window and queues its messages in the
//! outbox with their pair sequences; an acknowledgement clears the outbox
//! through its sequence. A write to a committed map writes its value row
//! with the new state version and a dirty row beside it, and the result's
//! seed is kept under that version, for the node's root builder: nothing
//! here hashes. A step's new session is created first, with its
//! row in the expiry index. A refused step applies nothing. A sweep
//! collects the sessions it lists that have expired, and moves the rows of
//! those active since. A work result built on another state version, timed
//! before the agent's latest, or holding a new session whose creation time
//! is far from its own or past a cap, applies nothing at all: refine
//! refuses such a session, so the result was not refined on this state as
//! it says.

use alloc::collections::{BTreeMap, BTreeSet};

use vos_wire::ids::{Session, SessionId, SessionRef};
use vos_wire::jam::AccumulateInput;
use vos_wire::records::{SessionMark, stored, stored_versioned, unstored};
use vos_wire::result::{InputRef, Run, Step, WorkResult};
use vos_wire::{Decode, Encode, defaults, expiry, keys};

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

/// A step's session, created when the step is its first, at `time`.
fn session(named: &SessionRef, time: u64) -> SessionId {
    let session = match named {
        SessionRef::Known(id) => return *id,
        SessionRef::New(session) => session,
    };
    // An earlier step of the same result may have created it.
    if let Some(id) = get::<SessionId>(&keys::session_index(session)) {
        return id;
    }
    let id = SessionId(get::<u64>(&keys::next_session()).unwrap_or(0));
    put(&keys::next_session(), &(id.0 + 1).encode());
    put(&keys::session_index(session), &id.encode());
    put(&keys::session_of(id), &session.encode());
    put(&keys::expiry(expiry::bucket(time), id), &[]);
    let live = get::<u64>(&keys::live_sessions()).unwrap_or(0);
    put(&keys::live_sessions(), &(live + 1).encode());
    let held = keys::key_sessions(&session.key);
    let count = get::<u64>(&held).unwrap_or(0);
    put(&held, &(count + 1).encode());
    id
}

/// The sessions `result`'s ran steps name whole: those it creates, each
/// as many times as steps name it.
fn new_sessions(result: &WorkResult) -> impl Iterator<Item = &Session> {
    result.steps.iter().filter_map(|step| match step {
        Step::Ran(Run {
            input:
                InputRef::Request {
                    session: SessionRef::New(session),
                    ..
                },
            ..
        }) => Some(&**session),
        _ => None,
    })
}

/// Whether the sessions `result` creates fit the caps.
fn within_caps(result: &WorkResult) -> bool {
    // Each created session once, counted under its key.
    let mut created = BTreeSet::new();
    let mut per_key: BTreeMap<&[u8; 32], u64> = BTreeMap::new();
    for session in new_sessions(result) {
        if created.insert(session) {
            *per_key.entry(&session.key).or_default() += 1;
        }
    }
    if created.is_empty() {
        return true;
    }
    let live = get::<u64>(&keys::live_sessions()).unwrap_or(0);
    if live.saturating_add(created.len() as u64) > defaults::MAX_SESSIONS {
        return false;
    }
    per_key.iter().all(|(key, new)| {
        get::<u64>(&keys::key_sessions(key))
            .unwrap_or(0)
            .saturating_add(*new)
            <= defaults::MAX_KEY_SESSIONS
    })
}

/// Whether a step of `result` creates a session far from its time.
fn stale(result: &WorkResult) -> bool {
    new_sessions(result).any(|session| session.t0.abs_diff(result.time) > defaults::SESSION_SKEW_MS)
}

fn apply(result: &WorkResult) {
    let version: u64 = get(&keys::version()).unwrap_or(0);
    if result.version != version {
        return;
    }
    let latest: u64 = get(&keys::batch_time()).unwrap_or(0);
    if result.time < latest || stale(result) || !within_caps(result) {
        return;
    }
    if result.time > latest {
        put(&keys::batch_time(), &result.time.encode());
    }
    let next = version + 1;
    let mut committed = false;
    for step in &result.steps {
        match step {
            Step::Ran(run) => {
                apply_run(run, result.time, next);
                committed |= !run.committed.is_empty();
            }
            Step::Swept { due } => sweep(due, result.time),
            Step::Refused { .. } => {}
        }
    }
    if committed {
        put(&keys::seed(next), &result.seed);
    }
    put(&keys::version(), &next.encode());
}

/// Take each listed expiry row out of the due range: collect its session
/// once it has expired and `time` is past its t0 plus the skew, else move
/// the row to where it is next due.
fn sweep(due: &[(u64, SessionId)], time: u64) {
    let before = get::<u64>(&keys::live_sessions()).unwrap_or(0);
    let mut live = before;
    for &(bucket, id) in due {
        let row = keys::expiry(bucket, id);
        let Some(mark) = get::<SessionMark>(&keys::session(id)) else {
            delete(&row);
            continue;
        };
        let whole = get::<Session>(&keys::session_of(id));
        // The latest time its t0 still lets it be created.
        let creatable = whole.map_or(0, |whole| {
            whole.t0.saturating_add(defaults::SESSION_SKEW_MS)
        });
        if time > mark.time.saturating_add(defaults::SESSION_EXPIRY_MS) && time > creatable {
            collect(id, mark, whole);
            delete(&row);
            live = live.saturating_sub(1);
        } else {
            let next = expiry::bucket(mark.time.max(creatable));
            if next != bucket {
                delete(&row);
                put(&keys::expiry(next, id), &[]);
            }
        }
    }
    if live != before {
        put(&keys::live_sessions(), &live.encode());
    }
}

/// Remove a session: its index row, whole, mark, kept replies and key
/// count. Without its whole, its index row and key count cannot be found,
/// and stay.
fn collect(id: SessionId, mark: SessionMark, whole: Option<Session>) {
    if let Some(whole) = whole {
        delete(&keys::session_index(&whole));
        delete(&keys::session_of(id));
        let held = keys::key_sessions(&whole.key);
        match get::<u64>(&held).unwrap_or(0) {
            0 => {}
            1 => delete(&held),
            count => put(&held, &(count - 1).encode()),
        }
    }
    delete(&keys::session(id));
    // The window: every sequence through the mark ran and kept its reply,
    // and the last `REPLY_WINDOW` are kept.
    let first = mark
        .sequence
        .saturating_sub(defaults::REPLY_WINDOW - 1)
        .max(1);
    for sequence in first..=mark.sequence {
        delete(&keys::reply(id, sequence));
    }
}

/// Apply a step's effects, its committed writes made at `version`.
fn apply_run(run: &Run, time: u64, version: u64) {
    let session = match &run.input {
        InputRef::Request { session: named, .. } => Some(session(named, time)),
        _ => None,
    };
    for item in &run.writes {
        match &item.value {
            Some(value) => put(&item.key, value),
            None => delete(&item.key),
        }
    }
    for item in &run.committed {
        let row = keys::committed(&item.map, &item.key);
        match &item.value {
            Some(value) => write(&row, &stored_versioned(version, value)),
            None => delete(&row),
        }
        put(&keys::dirty(version, &item.map, &item.key), &[]);
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
