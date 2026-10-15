//! Client sessions as refine admits a request into one: its session as
//! the state and this refine's earlier steps hold it, its order, its
//! expiry, and the caps a new session must fit.

use alloc::collections::BTreeMap;

use vos_wire::abi::Refusal;
use vos_wire::batch::Request;
use vos_wire::ids::{Session, SessionId, SessionRef};
use vos_wire::records::SessionMark;
use vos_wire::result::InputRef;
use vos_wire::{defaults, keys};

use super::base::{Base, Corrupt};

/// A request's session as this refine sees it.
#[derive(Clone, Copy)]
pub(super) enum Held {
    /// Neither the state holds it nor has a step created it.
    Absent,
    /// An earlier step of this refine created it: it has no id yet.
    New(SessionMark),
    /// The state holds it, under its id.
    Known(SessionId, SessionMark),
}

impl Held {
    fn mark(self) -> Option<SessionMark> {
        match self {
            Held::Absent => None,
            Held::New(mark) | Held::Known(_, mark) => Some(mark),
        }
    }

    /// The session once a step has run at `mark`.
    pub(super) fn advanced(self, mark: SessionMark) -> Held {
        match self {
            Held::Known(id, _) => Held::Known(id, mark),
            Held::Absent | Held::New(_) => Held::New(mark),
        }
    }
}

/// A session as the in-batch map orders it: by its name as a number
/// first, then its time, then its key, so sessions compare in a few
/// instructions and one key's many sessions differ at once.
pub(super) type ByName = (u128, u64, [u8; 32]);

pub(super) fn by_name(session: &Session) -> ByName {
    (u128::from_le_bytes(session.name), session.t0, session.key)
}

/// The sessions the agent holds, in all and per key, as this refine has
/// created them so far: the applied counts, each read once, and the
/// batch's.
#[derive(Default)]
pub(super) struct Counts {
    live: Option<u64>,
    keys: BTreeMap<[u8; 32], u64>,
}

impl Counts {
    /// The cap a new session of `key` would pass, if any.
    fn full(&mut self, base: &Base, key: &[u8; 32]) -> Result<Option<Refusal>, Corrupt> {
        let live = match self.live {
            Some(live) => live,
            None => *self
                .live
                .insert(base.record::<u64>(&keys::live_sessions())?.unwrap_or(0)),
        };
        if live >= defaults::MAX_SESSIONS {
            return Ok(Some(Refusal::SessionsFull));
        }
        let held = match self.keys.get(key) {
            Some(held) => *held,
            None => {
                let held = base.record::<u64>(&keys::key_sessions(key))?.unwrap_or(0);
                self.keys.insert(*key, held);
                held
            }
        };
        Ok((held >= defaults::MAX_KEY_SESSIONS).then_some(Refusal::KeySessionsFull))
    }

    /// A new session of `key`, which [`Counts::full`] let through.
    pub(super) fn add(&mut self, key: &[u8; 32]) {
        *self.live.as_mut().expect("the live count") += 1;
        *self.keys.get_mut(key).expect("the key's count") += 1;
    }
}

/// A session as applied state holds it.
fn held(base: &Base, session: &Session) -> Result<Held, Corrupt> {
    match base.record::<SessionId>(&keys::session_index_key(session))? {
        Some(id) => {
            let mark = base
                .record::<SessionMark>(&keys::session(id))?
                .ok_or(Corrupt)?;
            Ok(Held::Known(id, mark))
        }
        None => Ok(Held::Absent),
    }
}

/// A request against its session as this refine sees it: how the result
/// names the session, and the session before the step, or the code that
/// refuses the step. A session the step would create must fit the caps;
/// it counts toward them once the step is in the result ([`Counts::add`]).
pub(super) fn admit(
    base: &Base,
    sessions: &BTreeMap<ByName, Held>,
    counts: &mut Counts,
    request: &Request,
) -> (InputRef, Result<Held, Refusal>) {
    let held = match sessions.get(&by_name(&request.session)) {
        Some(held) => Ok(*held),
        None => held(base, &request.session),
    };
    // A session the state does not hold names itself whole.
    let session = match held {
        Ok(Held::Known(id, _)) => SessionRef::Known(id),
        _ => SessionRef::New(alloc::boxed::Box::new(request.session)),
    };
    let input = InputRef::Request {
        session,
        sequence: request.sequence,
    };
    let Ok(held) = held else {
        return (input, Err(Refusal::Unreadable));
    };
    let admitted = match held.mark() {
        // A duplicate first, even in an expired session: the leader
        // answers it from the window.
        Some(mark) if request.sequence <= mark.sequence => Err(Refusal::Sequence),
        Some(mark) if base.time > mark.time.saturating_add(defaults::SESSION_EXPIRY_MS) => {
            Err(Refusal::Expired)
        }
        Some(mark) if request.sequence != mark.sequence + 1 => Err(Refusal::Sequence),
        Some(_) => Ok(held),
        None if request.session.t0.abs_diff(base.time) > defaults::SESSION_SKEW_MS => {
            Err(Refusal::StaleSession)
        }
        None if request.sequence != 1 => Err(Refusal::Sequence),
        // Neither held nor created by an earlier step: this one creates
        // it, within the caps.
        None => match counts.full(base, &request.session.key) {
            Ok(None) => Ok(held),
            Ok(Some(code)) => Err(code),
            Err(Corrupt) => Err(Refusal::Unreadable),
        },
    };
    (input, admitted)
}
