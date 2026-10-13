//! Sessions: named by their client and created by accumulate, refused out
//! of order, stale or past their caps, kept with a window of replies, and
//! collected once expired, step by step and against a model of their life
//! cycle.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use vos_wire::Encode;
use vos_wire::abi::refusal;
use vos_wire::batch::Input;
use vos_wire::ids::{Session, SessionId, SessionRef};
use vos_wire::records::{SessionMark, stored};
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::{defaults, expiry, keys};

use crate::common::{Node, counter_only, done, increment_in, ran, ran_step, refused, setup};

/// The session whose key is `key`'s bytes and name `name`'s, created at
/// `t0`.
fn session(key: u8, name: u8, t0: u64) -> Session {
    Session {
        key: [key; 32],
        name: [name; 16],
        t0,
    }
}

fn swept(step: &Step) -> Vec<(u64, SessionId)> {
    match step {
        Step::Swept { due } => due.clone(),
        other => panic!("not a sweep: {other:?}"),
    }
}

#[test]
fn sessions_refuse_gaps_and_expiry_and_keep_a_reply_window() {
    let (actors, mut node, _, _) = setup();
    let session = session(9, 9, 1);
    let request = |sequence: u64| increment_in(&actors, session, sequence);
    let result = node.batch(1, vec![request(2), request(1), request(1), request(2)]);
    assert_eq!(refused(&result.steps[0]), refusal::SEQUENCE);
    assert_eq!(done::<u64>(&result.steps[1]), 1);
    assert_eq!(refused(&result.steps[2]), refusal::SEQUENCE);
    assert_eq!(done::<u64>(&result.steps[3]), 2);
    let (id, _) = node.session(&session).unwrap();
    assert_eq!(
        node.get(&keys::reply(id, 2)),
        Some(Outcome::Done(2u64.encode()).encode())
    );

    let later = 2 + defaults::SESSION_EXPIRY_MS;
    let result = node.batch(later, vec![request(3)]);
    assert_eq!(refused(&result.steps[0]), refusal::EXPIRED);
}

/// A session is its key, name and creation time: accumulate gives each a
/// compact id when its first request applies, and a step names a session
/// by that id once the state holds it. A new session must start at 1, near
/// the batch's time.
#[test]
fn sessions_are_named_by_their_client_and_created_by_accumulate() {
    let (actors, mut node, _, _) = setup();
    let now = 1_000_000;
    let (first, second) = (session(1, 1, now), session(1, 2, now - 30_000));
    let stale = session(1, 3, now - defaults::SESSION_SKEW_MS - 1);
    let ahead = session(1, 4, now + defaults::SESSION_SKEW_MS + 1);
    let request = |session: Session, sequence: u64| increment_in(&actors, session, sequence);
    let result = node.batch(
        now,
        vec![
            request(first, 1),
            request(second, 1),
            request(first, 2),
            request(stale, 1),
            request(ahead, 1),
            request(session(1, 5, now), 2),
            request(
                Session {
                    t0: now + 1,
                    ..first
                },
                1,
            ),
        ],
    );
    let named = |step: &Step| match step {
        Step::Ran(Run {
            input: InputRef::Request { session, .. },
            ..
        })
        | Step::Refused {
            input: InputRef::Request { session, .. },
            ..
        } => session.clone(),
        other => panic!("not a request: {other:?}"),
    };
    assert_eq!(named(&result.steps[0]), SessionRef::New(Box::new(first)));
    assert_eq!(named(&result.steps[2]), SessionRef::New(Box::new(first)));
    assert_eq!(done::<u64>(&result.steps[2]), 3);
    assert_eq!(refused(&result.steps[3]), refusal::STALE_SESSION);
    assert_eq!(refused(&result.steps[4]), refusal::STALE_SESSION);
    assert_eq!(
        refused(&result.steps[5]),
        refusal::SEQUENCE,
        "a new session starts at 1"
    );
    assert_eq!(
        done::<u64>(&result.steps[6]),
        4,
        "another t0 is another session"
    );

    let (one, mark) = node.session(&first).unwrap();
    assert_eq!(
        mark,
        SessionMark {
            sequence: 2,
            time: now
        }
    );
    assert_eq!(node.value::<Session>(&keys::session_of(one)), Some(first));
    let (two, _) = node.session(&second).unwrap();
    assert_ne!(one, two);
    assert_eq!(node.session(&stale), None);
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(3));
    assert_eq!(node.value::<u64>(&keys::next_session()), Some(3));
    assert_eq!(node.value::<u64>(&keys::batch_time()), Some(now));

    let result = node.batch(now + 5, vec![request(first, 3)]);
    assert_eq!(named(&result.steps[0]), SessionRef::Known(one));
    assert_eq!(done::<u64>(&result.steps[0]), 5);
    assert_eq!(node.session(&first).unwrap().1.sequence, 3);
}

/// Accumulate is the authority on time: a result with a new session far
/// from its time, or timed before the agent's latest, applies nothing at
/// all. Refine refuses such a session, so a later step may have been
/// refined as if that one had run.
#[test]
fn accumulate_skips_stale_sessions_and_results_from_the_past() {
    let (_, mut node, _, _) = setup();
    let now = 1_000_000;
    let (fresh, stale) = (session(2, 1, now), session(2, 2, 1));
    let step = |session: SessionRef, key: u8| {
        ran_step(
            session,
            1,
            vec![Write {
                key: vec![0x01, key],
                value: Some(vec![key]),
            }],
        )
    };
    let version = node.version;
    let applied = |node: &Node| {
        (
            node.value::<u64>(&keys::version()),
            node.value::<u64>(&keys::batch_time()),
        )
    };
    let before = applied(&node);
    let result = WorkResult {
        version,
        time: now,
        seed: [0; 32],
        steps: vec![
            step(SessionRef::New(Box::new(stale)), 1),
            step(SessionRef::New(Box::new(fresh)), 3),
        ],
    };
    node.accumulate(&result.encode());
    assert_eq!(node.get(&[0x01, 1]), None);
    assert_eq!(node.get(&[0x01, 3]), None);
    assert_eq!(node.session(&stale), None);
    assert_eq!(node.session(&fresh), None);
    assert_eq!(applied(&node), before, "nothing at all");

    let fresh_only = WorkResult {
        steps: vec![step(SessionRef::New(Box::new(fresh)), 3)],
        ..result
    };
    node.accumulate(&fresh_only.encode());
    assert_eq!(node.get(&[0x01, 3]), Some(vec![3]));
    assert_eq!(node.session(&fresh).unwrap().1.sequence, 1);
    assert_eq!(node.value::<u64>(&keys::version()), Some(version + 1));

    let past = WorkResult {
        version: version + 1,
        time: now - 1,
        seed: [0; 32],
        steps: vec![step(SessionRef::New(Box::new(session(2, 3, now))), 4)],
    };
    node.accumulate(&past.encode());
    assert_eq!(node.get(&[0x01, 4]), None);
    assert_eq!(node.value::<u64>(&keys::version()), Some(version + 1));
    assert_eq!(node.value::<u64>(&keys::batch_time()), Some(now));
}

/// A session leaves whole once it has expired and its expiry row is due:
/// its index, whole, mark, kept replies, row and counts. A session active
/// since has its row moved instead. Before collection an expired session
/// is refused `EXPIRED`, a duplicate of it `SEQUENCE` (the leader answers
/// it from the window); after, its requests name a stale t0 and never run.
#[test]
fn sessions_are_collected_once_expired_and_moved_while_active() {
    let (actors, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let bucket = expiry::bucket(now);
    let (idle, active) = (session(3, 1, now), session(3, 2, now));
    node.batch(
        now,
        vec![
            increment_in(&actors, idle, 1),
            increment_in(&actors, idle, 2),
            increment_in(&actors, active, 1),
        ],
    );
    let (idle_id, _) = node.session(&idle).unwrap();
    let (active_id, _) = node.session(&active).unwrap();
    for id in [idle_id, active_id] {
        assert_eq!(node.get(&keys::expiry(bucket, id)), Some(Vec::new()));
    }
    assert_eq!(node.value::<u64>(&keys::key_sessions(&[3; 32])), Some(2));

    let later = now + defaults::SESSION_EXPIRY_MS / 2;
    node.batch(later, vec![increment_in(&actors, active, 2)]);
    assert_eq!(
        node.get(&keys::expiry(bucket, active_id)),
        Some(Vec::new()),
        "a request does not move its row"
    );

    let due = expiry::due(bucket);
    let result = node.batch(due - 1, vec![Input::Sweep]);
    assert_eq!(swept(&result.steps[0]), Vec::new(), "not due yet");
    let result = node.batch(
        due - 1,
        vec![
            increment_in(&actors, idle, 3),
            increment_in(&actors, idle, 2),
        ],
    );
    assert_eq!(refused(&result.steps[0]), refusal::EXPIRED);
    assert_eq!(refused(&result.steps[1]), refusal::SEQUENCE);

    let result = node.batch(due, vec![Input::Sweep]);
    assert_eq!(
        swept(&result.steps[0]),
        vec![(bucket, idle_id), (bucket, active_id)]
    );
    assert_eq!(node.session(&idle), None);
    assert_eq!(node.get(&keys::session_of(idle_id)), None);
    assert_eq!(node.get(&keys::session(idle_id)), None);
    for sequence in 1..=2 {
        assert_eq!(node.get(&keys::reply(idle_id, sequence)), None);
    }
    assert_eq!(node.get(&keys::expiry(bucket, idle_id)), None);
    assert_eq!(node.get(&keys::expiry(bucket, active_id)), None);
    assert_eq!(
        node.get(&keys::expiry(expiry::bucket(later), active_id)),
        Some(Vec::new()),
        "moved to its mark's bucket"
    );
    assert!(node.session(&active).is_some());
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(1));
    assert_eq!(node.value::<u64>(&keys::key_sessions(&[3; 32])), Some(1));

    let result = node.batch(
        due + 1,
        vec![
            increment_in(&actors, idle, 3),
            increment_in(&actors, idle, 1),
            increment_in(&actors, session(3, 3, due), 1),
        ],
    );
    assert_eq!(refused(&result.steps[0]), refusal::STALE_SESSION);
    assert_eq!(refused(&result.steps[1]), refusal::STALE_SESSION);
    assert_eq!(done::<u64>(&result.steps[2]), 5, "the collected ran 2");
    assert_eq!(
        node.session(&session(3, 3, due)).unwrap().0,
        SessionId(2),
        "ids are never reused"
    );

    // The moved row comes due in its turn, and the active session goes.
    let due = expiry::due(expiry::bucket(later));
    let result = node.batch(due, vec![Input::Sweep]);
    assert_eq!(
        swept(&result.steps[0]),
        vec![(expiry::bucket(later), active_id)]
    );
    assert_eq!(node.session(&active), None);
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(1));
}

/// The caps refuse a new session, never evict one, counting the sessions
/// a batch creates; collection makes room again, a sweep at a time.
#[test]
fn session_caps_refuse_new_sessions_until_some_are_collected() {
    let (actors, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let one_key = |name: u64| Session {
        key: [4; 32],
        name: u128::from(name).to_le_bytes(),
        t0: now,
    };
    let other = session(5, 0, now);
    let mut inputs: Vec<Input> = (0..=defaults::MAX_KEY_SESSIONS)
        .map(|name| increment_in(&actors, one_key(name), 1))
        .collect();
    inputs.push(increment_in(&actors, other, 1));
    let result = node.batch(now, inputs);
    let cap = defaults::MAX_KEY_SESSIONS as usize;
    for step in &result.steps[..cap] {
        ran(step);
    }
    assert_eq!(refused(&result.steps[cap]), refusal::KEY_SESSIONS_FULL);
    ran(&result.steps[cap + 1]);
    assert_eq!(
        node.value::<u64>(&keys::key_sessions(&[4; 32])),
        Some(defaults::MAX_KEY_SESSIONS)
    );
    let result = node.batch(now + 1, vec![increment_in(&actors, one_key(999), 1)]);
    assert_eq!(refused(&result.steps[0]), refusal::KEY_SESSIONS_FULL);

    // The agent's cap, at one session from it.
    let live = cap as u64 + 1;
    node.state.insert(
        keys::live_sessions(),
        stored(&(defaults::MAX_SESSIONS - 1).encode()),
    );
    let result = node.batch(
        now + 2,
        vec![
            increment_in(&actors, session(6, 0, now), 1),
            increment_in(&actors, session(7, 0, now), 1),
            increment_in(&actors, session(6, 0, now), 2),
        ],
    );
    ran(&result.steps[0]);
    assert_eq!(refused(&result.steps[1]), refusal::SESSIONS_FULL);
    ran(&result.steps[2]);
    node.state
        .insert(keys::live_sessions(), stored(&(live + 1).encode()));

    // Past expiry, a sweep at a time, at most `SWEEP_LIMIT` each.
    let due = expiry::due(expiry::bucket(now));
    let mut sweeps = 0;
    loop {
        let result = node.batch(due, vec![Input::Sweep]);
        let listed = swept(&result.steps[0]).len();
        assert!(listed <= defaults::SWEEP_LIMIT);
        if listed == 0 {
            break;
        }
        sweeps += 1;
    }
    assert_eq!(sweeps, (live as usize + 1).div_ceil(defaults::SWEEP_LIMIT));
    assert_eq!(node.value::<u64>(&keys::live_sessions()), Some(0));
    assert_eq!(node.get(&keys::key_sessions(&[4; 32])), None);
    let result = node.batch(
        due + 1,
        vec![increment_in(
            &actors,
            Session {
                t0: due,
                ..one_key(999)
            },
            1,
        )],
    );
    ran(&result.steps[0]);
}

/// Accumulate checks the caps itself, counting each new session once, and
/// takes every row a sweep lists out of the due range, whatever the state
/// holds of its session.
#[test]
fn accumulate_holds_the_caps_and_clears_the_rows_a_sweep_lists() {
    let (_, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let version = |node: &Node| node.value::<u64>(&keys::version()).unwrap_or(0);
    node.state.insert(
        keys::live_sessions(),
        stored(&(defaults::MAX_SESSIONS - 1).encode()),
    );
    let two = WorkResult {
        version: version(&node),
        time: now,
        seed: [0; 32],
        steps: vec![
            ran_step(SessionRef::New(Box::new(session(6, 1, now))), 1, Vec::new()),
            ran_step(SessionRef::New(Box::new(session(6, 2, now))), 1, Vec::new()),
        ],
    };
    let before = version(&node);
    node.accumulate(&two.encode());
    assert_eq!(version(&node), before, "past the agent's cap: nothing");
    assert_eq!(node.session(&session(6, 1, now)), None);
    let one = WorkResult {
        steps: vec![
            ran_step(SessionRef::New(Box::new(session(6, 1, now))), 1, Vec::new()),
            ran_step(SessionRef::New(Box::new(session(6, 1, now))), 2, Vec::new()),
        ],
        ..two.clone()
    };
    node.accumulate(&one.encode());
    assert_eq!(version(&node), before + 1, "one session, named twice");
    assert_eq!(node.session(&session(6, 1, now)).unwrap().1.sequence, 2);
    assert_eq!(
        node.value::<u64>(&keys::live_sessions()),
        Some(defaults::MAX_SESSIONS)
    );

    // A row listed early stays; a row without a session goes; a session
    // without its whole loses all the triple does not name.
    let (id, _) = node.session(&session(6, 1, now)).unwrap();
    let bucket = expiry::bucket(now);
    let orphan = (bucket, SessionId(99));
    node.state
        .insert(keys::expiry(orphan.0, orphan.1), stored(&[]));
    let sweep = |time: u64, version: u64| WorkResult {
        version,
        time,
        seed: [0; 32],
        steps: vec![Step::Swept {
            due: vec![orphan, (bucket, id)],
        }],
    };
    node.accumulate(&sweep(now + 1, version(&node)).encode());
    assert_eq!(node.get(&keys::expiry(orphan.0, orphan.1)), None);
    assert_eq!(node.get(&keys::expiry(bucket, id)), Some(Vec::new()));
    node.state.remove(&keys::session_of(id));
    let due = expiry::due(bucket);
    node.accumulate(&sweep(due, version(&node)).encode());
    assert_eq!(node.get(&keys::session(id)), None);
    assert_eq!(node.get(&keys::reply(id, 1)), None);
    assert_eq!(node.get(&keys::reply(id, 2)), None);
    assert_eq!(node.get(&keys::expiry(bucket, id)), None);
    assert!(
        node.get(&keys::session_index(&session(6, 1, now)))
            .is_some(),
        "the index needs the triple"
    );
    assert_eq!(
        node.value::<u64>(&keys::live_sessions()),
        Some(defaults::MAX_SESSIONS - 1)
    );
}

/// Refine lists due rows by their keys alone: a key under the index that
/// is not an expiry key is passed over, and a row whose value was not
/// stored is listed like any.
#[test]
fn refine_lists_due_rows_by_their_keys() {
    let (actors, mut node, _, _) = setup();
    let now = 100 * defaults::SESSION_BUCKET_MS;
    let session = session(8, 8, now);
    node.batch(now, vec![increment_in(&actors, session, 1)]);
    let (id, _) = node.session(&session).unwrap();
    let mut malformed = keys::expiry_prefix();
    malformed.extend_from_slice(&[0; 3]);
    node.state.insert(malformed.clone(), stored(&[]));
    node.state
        .insert(keys::expiry(expiry::bucket(now), id), vec![0xff]);
    let due = expiry::due(expiry::bucket(now));
    let result = node.batch(due, vec![Input::Sweep]);
    assert_eq!(swept(&result.steps[0]), vec![(expiry::bucket(now), id)]);
    assert_eq!(node.session(&session), None);
    assert!(node.state.contains_key(&malformed));
}

/// The agent's session state, every row of it.
fn session_rows(node: &Node) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let any = session(0, 0, 0);
    let tags: Vec<Vec<u8>> = [
        keys::session(SessionId(0)),
        keys::reply(SessionId(0), 0),
        keys::session_index(&any),
        keys::session_of(SessionId(0)),
        keys::expiry_prefix(),
        keys::key_sessions(&[0; 32]),
        keys::live_sessions(),
        keys::next_session(),
    ]
    .iter()
    .map(|key| key[..2].to_vec())
    .collect();
    node.state
        .iter()
        .filter(|(key, _)| tags.iter().any(|tag| key.starts_with(tag)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// A session as the model holds it.
#[derive(Clone, Debug)]
struct Modelled {
    id: SessionId,
    sequence: u64,
    time: u64,
    /// The replies kept, by sequence.
    replies: BTreeMap<u64, u64>,
}

/// The agent's sessions as the plan defines them, step by step.
#[derive(Clone, Default)]
struct SessionModel {
    sessions: BTreeMap<Session, Modelled>,
    rows: BTreeSet<(u64, SessionId)>,
    next: u64,
    created: bool,
    total: u64,
}

impl SessionModel {
    fn live(&self) -> u64 {
        self.sessions.len() as u64
    }

    fn of_key(&self, key: &[u8; 32]) -> u64 {
        self.sessions
            .keys()
            .filter(|session| session.key == *key)
            .count() as u64
    }

    /// What the sweep lists at `time`, and what it does.
    fn sweep(&mut self, time: u64) -> Vec<(u64, SessionId)> {
        let due: Vec<(u64, SessionId)> = self
            .rows
            .iter()
            .take_while(|(bucket, _)| expiry::due(*bucket) <= time)
            .take(defaults::SWEEP_LIMIT)
            .copied()
            .collect();
        for &(bucket, id) in &due {
            self.rows.remove(&(bucket, id));
            let (session, modelled) = self
                .sessions
                .iter()
                .find(|(_, modelled)| modelled.id == id)
                .map(|(session, modelled)| (*session, modelled.clone()))
                .expect("a row's session");
            let creatable = session.t0 + defaults::SESSION_SKEW_MS;
            if time > modelled.time + defaults::SESSION_EXPIRY_MS && time > creatable {
                self.sessions.remove(&session);
            } else {
                self.rows
                    .insert((expiry::bucket(modelled.time.max(creatable)), id));
            }
        }
        due
    }

    /// A request's step in a batch at `time`, as refine decides it: run,
    /// or refused with a code.
    fn refine(&mut self, session: Session, sequence: u64, time: u64) -> Result<(), u32> {
        match self.sessions.get(&session) {
            Some(held) if sequence <= held.sequence => return Err(refusal::SEQUENCE),
            Some(held) if time > held.time + defaults::SESSION_EXPIRY_MS => {
                return Err(refusal::EXPIRED);
            }
            Some(held) if sequence != held.sequence + 1 => return Err(refusal::SEQUENCE),
            Some(_) => {}
            None if session.t0.abs_diff(time) > defaults::SESSION_SKEW_MS => {
                return Err(refusal::STALE_SESSION);
            }
            None if sequence != 1 => return Err(refusal::SEQUENCE),
            None if self.live() >= defaults::MAX_SESSIONS => {
                return Err(refusal::SESSIONS_FULL);
            }
            None if self.of_key(&session.key) >= defaults::MAX_KEY_SESSIONS => {
                return Err(refusal::KEY_SESSIONS_FULL);
            }
            None => {}
        }
        self.apply(session, sequence, time);
        Ok(())
    }

    /// A request that ran, as accumulate applies it: its session created
    /// if the state does not hold it, its mark and reply.
    fn apply(&mut self, session: Session, sequence: u64, time: u64) {
        self.total += 1;
        let total = self.total;
        let modelled = match self.sessions.get_mut(&session) {
            Some(modelled) => modelled,
            None => {
                let id = SessionId(self.next);
                self.next += 1;
                self.created = true;
                self.rows.insert((expiry::bucket(time), id));
                self.sessions.entry(session).or_insert(Modelled {
                    id,
                    sequence: 0,
                    time,
                    replies: BTreeMap::new(),
                })
            }
        };
        modelled.sequence = sequence;
        modelled.time = time;
        modelled.replies.insert(sequence, total);
        if let Some(old) = sequence.checked_sub(defaults::REPLY_WINDOW) {
            modelled.replies.remove(&old);
        }
    }

    /// The rows the agent should hold.
    fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut rows = BTreeMap::new();
        let mut keys_held: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (session, modelled) in &self.sessions {
            let id = modelled.id;
            rows.insert(keys::session_index(session), stored(&id.encode()));
            rows.insert(keys::session_of(id), stored(&session.encode()));
            let mark = SessionMark {
                sequence: modelled.sequence,
                time: modelled.time,
            };
            rows.insert(keys::session(id), stored(&mark.encode()));
            for (sequence, total) in &modelled.replies {
                rows.insert(
                    keys::reply(id, *sequence),
                    stored(&Outcome::Done(total.encode()).encode()),
                );
            }
            *keys_held.entry(session.key).or_default() += 1;
        }
        for (bucket, id) in &self.rows {
            rows.insert(keys::expiry(*bucket, *id), stored(&[]));
        }
        for (key, count) in keys_held {
            rows.insert(keys::key_sessions(&key), stored(&count.encode()));
        }
        if self.created {
            rows.insert(keys::live_sessions(), stored(&self.live().encode()));
            rows.insert(keys::next_session(), stored(&self.next.encode()));
        }
        rows
    }
}

/// A request's choices in a life-cycle batch: key, name, t0, sequence.
type LifeRequest = (u8, u8, u8, u8);

/// One batch of the session life cycle: how far time moves, whether it
/// sweeps, and its requests.
type LifeBatch = (u8, bool, Vec<LifeRequest>);

fn life_batch() -> impl Strategy<Value = LifeBatch> {
    (
        0u8..6,
        any::<bool>(),
        proptest::collection::vec((0u8..2, 0u8..2, 0u8..6, 0u8..5), 0..5),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Sessions live, expire, move and are collected as the model says,
    /// and every session row and count the agent holds is the model's
    /// after every batch.
    #[test]
    fn the_session_life_cycle_matches_the_model(
        batches in proptest::collection::vec(life_batch(), 1..14)
    ) {
        let (actors, mut node) = counter_only(Node::new());
        let mut model = SessionModel::default();
        let mut time = 100 * defaults::SESSION_BUCKET_MS;
        // The t0 each (key, name) first went with, to send it again.
        let mut first: BTreeMap<(u8, u8), u64> = BTreeMap::new();
        for (advance, sweep, requests) in batches {
            time += match advance {
                0 => 1_000,
                1 => defaults::SESSION_SKEW_MS * 3 / 2,
                2 => defaults::SESSION_BUCKET_MS,
                3 => defaults::SESSION_EXPIRY_MS / 2 + defaults::SESSION_BUCKET_MS,
                _ => defaults::SESSION_EXPIRY_MS + defaults::SESSION_BUCKET_MS,
            };
            let mut inputs = Vec::new();
            if sweep {
                inputs.push(Input::Sweep);
            }
            let mut requested = Vec::new();
            for (key, name, t0, sequence) in requests {
                // Mostly a session sent before, so sessions live on.
                let t0 = match t0 {
                    0 => time,
                    1 => time - defaults::SESSION_SKEW_MS / 2,
                    2 => time - 2 * defaults::SESSION_SKEW_MS,
                    _ => *first.get(&(key, name)).unwrap_or(&time),
                };
                first.entry((key, name)).or_insert(t0);
                let session = session(10 + key, name, t0);
                let mark = model.sessions.get(&session).map_or(0, |held| held.sequence);
                let sequence = match sequence {
                    0 | 1 => mark + 1,
                    2 => mark.max(1),
                    3 => mark + 2,
                    _ => 1,
                };
                requested.push((session, sequence));
                inputs.push(increment_in(&actors, session, sequence));
            }
            // Refine decides every step on the state before the batch;
            // accumulate sweeps first, then applies the steps that ran.
            let mut refined = model.clone();
            let expected: Vec<Result<(), u32>> = requested
                .iter()
                .map(|(session, sequence)| refined.refine(*session, *sequence, time))
                .collect();
            let listed = sweep.then(|| model.sweep(time));
            for ((session, sequence), expected) in requested.iter().zip(&expected) {
                if expected.is_ok() {
                    model.apply(*session, *sequence, time);
                }
            }
            let result = node.batch(time, inputs);
            let mut steps = result.steps.iter();
            if let Some(listed) = &listed {
                prop_assert_eq!(&swept(steps.next().unwrap()), listed);
            }
            for (step, expected) in steps.zip(&expected) {
                match expected {
                    Ok(()) => {
                        ran(step);
                    }
                    Err(code) => prop_assert_eq!(refused(step), *code),
                }
            }
            prop_assert_eq!(session_rows(&node), model.rows());
        }
    }
}
