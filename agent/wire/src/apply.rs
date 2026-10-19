//! Applying a work result to an agent's state: a VOS node's accumulate
//! does it, and on JAM refine does it over its witness, and the builder
//! over its store.
//!
//! Each step that ran writes its writes, advances its session or pair mark,
//! keeps its reply in the session's window and queues its messages in the
//! outbox with their pair sequences; an acknowledgement clears the outbox
//! through its sequence. A write to a committed map writes its value row
//! with the new state version; on a VOS node a dirty row goes beside it,
//! and the result's seed is kept under that version, for the node's root
//! builder: nothing here hashes. A step's new session is created first,
//! with its row in the due index. A workflow's step writes the pages its
//! snapshot stores and deletes those back at their base. A refused step
//! applies nothing. A sweep collects the sessions it lists that have
//! expired, and moves the rows of those active since. A work result built
//! on another state version, timed before the agent's latest, or holding
//! a new session whose creation time is far from its own or past a cap,
//! applies nothing at all: refine refuses such a session, so the result
//! was not refined on this state as it says. Nor does one applied to an
//! agent whose record (its target, space and clock, which its first
//! install writes together) is stored in part: the state is corrupt.
//!
//! In an agent of a space, a result records the cut of each window whose
//! boundary its time crosses ([`cut_windows`]): `cut(w)`, the state version
//! before it ([`keys::cut`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::abi::cap::Target;
use crate::ids::{Session, SessionId, SessionRef};
use crate::keys::Due;
use crate::records::{SessionMark, stored, stored_versioned, unstored};
use crate::result::{InputRef, Page, Run, Step, WorkResult};
use crate::{Decode, Encode, defaults, expiry, keys};
use crate::{SpaceId, WindowClock};

/// The agent's rows as apply reads and writes them, each as stored.
pub trait State {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    /// Set a row, or (`None`) delete it.
    fn write(&mut self, key: &[u8], value: Option<&[u8]>);
}

/// Where the rows that differ between hosts go.
#[derive(Clone, Copy, Debug)]
pub enum Host<'a> {
    /// A VOS node: a page row holds the page's LZ4 bytes, from the refine
    /// output's page section, and a committed write leaves a dirty row and
    /// its version's seed for the root builder.
    Vos { pages: &'a [Vec<u8>] },
    /// JAM: one tree over the whole keyspace, which refine updates as it
    /// applies, so no dirty or seed row; a page row holds the page's hash,
    /// and the page itself travels as a segment.
    Jam,
}

/// Apply `result` to `state`; false, with nothing written, when it does
/// not apply to it. One copy serves every host's state.
pub fn apply(state: &mut dyn State, result: &WorkResult, host: Host) -> bool {
    Apply { state, host }.result(result)
}

struct Apply<'a> {
    state: &'a mut dyn State,
    host: Host<'a>,
}

impl Apply<'_> {
    fn get<T: Decode>(&mut self, key: &[u8]) -> Option<T> {
        let bytes = self.state.read(key)?;
        let value = unstored(&bytes)?;
        T::decode(value).ok().map(|(value, _)| value)
    }

    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.state.write(key, Some(&stored(value)));
    }

    fn delete(&mut self, key: &[u8]) {
        self.state.write(key, None);
    }

    fn result(&mut self, result: &WorkResult) -> bool {
        let version: u64 = self.get(&keys::version()).unwrap_or(0);
        if result.version != version {
            return false;
        }
        let latest: u64 = self.get(&keys::batch_time()).unwrap_or(0);
        if result.time < latest || stale(result) || !self.within_caps(result) {
            return false;
        }
        // Read before the steps: the install that writes it cuts nothing.
        let Some(clock) = self.record() else {
            return false;
        };
        if result.time > latest {
            self.put(&keys::batch_time(), &result.time.encode());
        }
        let next = version + 1;
        let mut committed = false;
        let mut pages = match self.host {
            Host::Vos { pages } => pages,
            Host::Jam => &[],
        }
        .iter();
        for step in &result.steps {
            match step {
                Step::Ran(run) => {
                    self.run(run, result.time, next, &mut pages);
                    committed |= !run.committed.is_empty();
                }
                Step::Swept { due } => self.sweep(due, result.time),
                Step::Refused { .. } => {}
            }
        }
        if committed && let Host::Vos { .. } = self.host {
            self.put(&keys::seed(next), &result.seed);
        }
        if let Some((first, last)) =
            clock.and_then(|clock| cut_windows(&clock, latest, result.time))
        {
            for window in first..=last {
                self.put(&keys::cut(window), &version.encode());
            }
        }
        self.put(&keys::version(), &next.encode());
        true
    }

    /// The clock of the agent's space, `Some(None)` for an agent of no
    /// space or none yet; `None` when its record is stored in part, or does
    /// not decode.
    fn record(&mut self) -> Option<Option<WindowClock>> {
        let rows = [keys::target(), keys::space(), keys::clock()].map(|key| self.state.read(&key));
        match rows {
            [None, None, None] => Some(None),
            [Some(target), Some(space), Some(clock)] => {
                let value = |bytes: &[u8]| unstored(bytes).map(<[u8]>::to_vec);
                Target::decode_exact(&value(&target)?)?;
                let space = SpaceId::decode_exact(&value(&space)?)?;
                let clock = WindowClock::decode_exact(&value(&clock)?)?;
                Some((space != SpaceId::NONE).then_some(clock))
            }
            _ => None,
        }
    }

    /// A step's session, created when the step is its first, at `time`.
    fn session(&mut self, named: &SessionRef, time: u64) -> SessionId {
        let session = match named {
            SessionRef::Known(id) => return *id,
            SessionRef::New(session) => session,
        };
        // An earlier step of the same result may have created it.
        if let Some(id) = self.get::<SessionId>(&keys::session_index(session)) {
            return id;
        }
        let id = SessionId(self.get::<u64>(&keys::next_session()).unwrap_or(0));
        self.put(&keys::next_session(), &(id.0 + 1).encode());
        self.put(&keys::session_index(session), &id.encode());
        self.put(&keys::session_of(id), &session.encode());
        self.put(&keys::due(expiry::at(time), Due::Session(id)), &[]);
        let live = self.get::<u64>(&keys::live_sessions()).unwrap_or(0);
        self.put(&keys::live_sessions(), &(live + 1).encode());
        let held = keys::key_sessions(&session.key);
        let count = self.get::<u64>(&held).unwrap_or(0);
        self.put(&held, &(count + 1).encode());
        id
    }

    /// Whether the sessions `result` creates fit the caps.
    fn within_caps(&mut self, result: &WorkResult) -> bool {
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
        let live = self.get::<u64>(&keys::live_sessions()).unwrap_or(0);
        if live.saturating_add(created.len() as u64) > defaults::MAX_SESSIONS {
            return false;
        }
        per_key.iter().all(|(key, new)| {
            self.get::<u64>(&keys::key_sessions(key))
                .unwrap_or(0)
                .saturating_add(*new)
                <= defaults::MAX_KEY_SESSIONS
        })
    }

    /// Take each listed session's row out of the due range: collect the
    /// session once it has expired and `time` is past its t0 plus the
    /// skew, else move the row to where it is next due.
    fn sweep(&mut self, due: &[(u64, SessionId)], time: u64) {
        let before = self.get::<u64>(&keys::live_sessions()).unwrap_or(0);
        let mut live = before;
        for &(at, id) in due {
            let row = keys::due(at, Due::Session(id));
            let Some(mark) = self.get::<SessionMark>(&keys::session(id)) else {
                self.delete(&row);
                continue;
            };
            let whole = self.get::<Session>(&keys::session_of(id));
            // The latest time its t0 still lets it be created.
            let creatable = whole.map_or(0, |whole| {
                whole.t0.saturating_add(defaults::SESSION_SKEW_MS)
            });
            if time > mark.time.saturating_add(defaults::SESSION_EXPIRY_MS) && time > creatable {
                self.collect(id, mark, whole);
                self.delete(&row);
                live = live.saturating_sub(1);
            } else {
                let next = expiry::at(mark.time.max(creatable));
                if next != at {
                    self.delete(&row);
                    self.put(&keys::due(next, Due::Session(id)), &[]);
                }
            }
        }
        if live != before {
            self.put(&keys::live_sessions(), &live.encode());
        }
    }

    /// Remove a session: its index row, whole, mark, kept replies and key
    /// count. Without its whole, its index row and key count cannot be
    /// found, and stay.
    fn collect(&mut self, id: SessionId, mark: SessionMark, whole: Option<Session>) {
        if let Some(whole) = whole {
            self.delete(&keys::session_index(&whole));
            self.delete(&keys::session_of(id));
            let held = keys::key_sessions(&whole.key);
            match self.get::<u64>(&held).unwrap_or(0) {
                0 => {}
                1 => self.delete(&held),
                count => self.put(&held, &(count - 1).encode()),
            }
        }
        self.delete(&keys::session(id));
        // The window: every sequence through the mark ran and kept its
        // reply, and the last `REPLY_WINDOW` are kept.
        let first = mark
            .sequence
            .saturating_sub(defaults::REPLY_WINDOW - 1)
            .max(1);
        for sequence in first..=mark.sequence {
            self.delete(&keys::reply(id, sequence));
        }
    }

    /// Apply a step's effects, its committed writes made at `version`, and
    /// the pages it stores, those on a VOS node from `section`, the
    /// result's page section.
    fn run<'p>(
        &mut self,
        run: &Run,
        time: u64,
        version: u64,
        section: &mut impl Iterator<Item = &'p Vec<u8>>,
    ) {
        let session = match &run.input {
            InputRef::Request { session: named, .. } => Some(self.session(named, time)),
            _ => None,
        };
        for item in &run.writes {
            match &item.value {
                Some(value) => self.put(&item.key, value),
                None => self.delete(&item.key),
            }
        }
        for item in &run.committed {
            let row = keys::committed(&item.map, &item.key);
            match &item.value {
                Some(value) => self
                    .state
                    .write(&row, Some(&stored_versioned(version, value))),
                None => self.delete(&row),
            }
            if let Host::Vos { .. } = self.host {
                self.put(&keys::dirty(version, &row), &[]);
            }
        }
        for page in &run.pages {
            self.page(page, section);
        }
        match run.input {
            InputRef::Request { sequence, .. } => {
                let id = session.expect("a request's session");
                let mark = SessionMark { sequence, time };
                self.put(&keys::session(id), &mark.encode());
                self.put(&keys::reply(id, sequence), &run.outcome.encode());
                if let Some(old) = sequence.checked_sub(defaults::REPLY_WINDOW) {
                    self.delete(&keys::reply(id, old));
                }
            }
            InputRef::Message { from, sequence } => {
                self.put(&keys::pair_in(from), &sequence.encode());
            }
            InputRef::Admin | InputRef::Due { .. } => {}
            InputRef::Ack { to, sequence } => {
                // Monotonic and idempotent: a stale ack does nothing, one
                // past what was sent stops there, and one ack clears at most
                // `ACK_LIMIT` entries; the node acks again for the rest.
                let acked = self.get::<u64>(&keys::acked(to)).unwrap_or(0);
                let sent = self.get::<u64>(&keys::pair_out(to)).unwrap_or(0);
                let through = sequence
                    .min(sent)
                    .min(acked.saturating_add(defaults::ACK_LIMIT));
                for cleared in acked + 1..=through {
                    self.delete(&keys::outbox(to, cleared));
                }
                if through > acked {
                    self.put(&keys::acked(to), &through.encode());
                }
            }
        }
        for message in &run.messages {
            let next = self.get::<u64>(&keys::pair_out(message.to)).unwrap_or(0) + 1;
            self.put(&keys::outbox(message.to, next), &message.encode());
            self.put(&keys::pair_out(message.to), &next.encode());
        }
    }

    /// A page's row: stored or dropped.
    fn page<'p>(&mut self, page: &Page, section: &mut impl Iterator<Item = &'p Vec<u8>>) {
        let row = keys::page(page.workflow, page.index);
        match (page.hash, self.host) {
            (None, _) => self.delete(&row),
            (Some(_), Host::Vos { .. }) => {
                let bytes = section.next().expect("a stored page's bytes");
                self.put(&row, bytes);
            }
            (Some(hash), Host::Jam) => self.put(&row, &hash),
        }
    }
}

/// The windows a result timed `time` cuts, after one timed `mark`, the
/// agent's batch-time mark, on `clock`: each w with `mark < B_w ≤ time`, at
/// most the newest [`defaults::MAX_CUTS`] of them; the first and the last,
/// or none.
pub fn cut_windows(clock: &WindowClock, mark: u64, time: u64) -> Option<(u64, u64)> {
    // The last: the window before the one holding `time`.
    let last = clock.window(time)?.checked_sub(1)?;
    // The first: the window holding `mark`, whose boundary is past it.
    let first = clock.window(mark).unwrap_or(0);
    let first = first.max(last.saturating_sub(defaults::MAX_CUTS - 1));
    (first <= last).then_some((first, last))
}

/// The sessions `result`'s ran steps name whole: those it creates, each as
/// many times as steps name it.
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

/// Whether a step of `result` creates a session far from its time.
fn stale(result: &WorkResult) -> bool {
    new_sessions(result).any(|session| session.t0.abs_diff(result.time) > defaults::SESSION_SKEW_MS)
}
