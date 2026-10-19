//! A venue modelled as plain data, which the golden fixtures are judged
//! against: its id, its time, the formats it accepts, its registered spaces
//! and their ranges, its anchored roots and its `Seen` entries, as lists
//! ([`Policy`]); and a judgement's input as one byte string ([`Input`],
//! then the proof), which the harnesses hand every venue alike, natively,
//! in Wasm and on the JAM-only host. A real venue, Kreivo's pallet, keeps
//! the same checks over its storage and pins the program by the kernel its
//! call names.

use alloc::vec::Vec;

use crate::{
    Admitted, DecodeError, MAX_ROOT_AGE_MS, Pin, Refusal, RootRead, SpaceId, Statement,
    StatementId, Venue, VenueId, WindowClock, admit, decode_program, judge, seen_expiry,
};
use vos_anchor::codec::{self, Reader};

/// The windows a venue anchors for a space: from its registration's start
/// window, until the window its migration away starts at (exclusive), if
/// it migrated (`vos_anchor::Migrate::from_window`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub from: u64,
    pub until: Option<u64>,
}

impl Range {
    /// Whether `window` is within it.
    pub fn contains(&self, window: u64) -> bool {
        self.from <= window && self.until.is_none_or(|until| window < until)
    }
}

/// A space registered at the venue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub id: SpaceId,
    /// Its clock, from its genesis.
    pub clock: WindowClock,
    /// The windows the venue anchors for it.
    pub range: Range,
}

impl Space {
    /// The bytes of its encoding, at least: an absent end.
    const MIN_BYTES: usize = 32 + WindowClock::BYTES + 8 + 1;

    /// Its encoding: its id, its clock, its range's start, then 0, or 1 and
    /// its end.
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.0);
        self.clock.encode_to(out);
        out.extend_from_slice(&self.range.from.to_le_bytes());
        match self.range.until {
            None => out.push(0),
            Some(until) => {
                out.push(1);
                out.extend_from_slice(&until.to_le_bytes());
            }
        }
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let id = SpaceId(reader.array()?);
        let clock = WindowClock::decode_from(reader)?;
        let from = reader.u64()?;
        let until = if flag(reader)? {
            Some(reader.u64()?)
        } else {
            None
        };
        Ok(Self {
            id,
            clock,
            range: Range { from, until },
        })
    }
}

/// A venue's state as lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Its id.
    pub venue: VenueId,
    /// Its time: milliseconds since the Unix epoch, by its own clock.
    pub now_ms: u64,
    /// The formats it accepts.
    pub formats: Vec<u32>,
    /// Its registered spaces.
    pub spaces: Vec<Space>,
    /// Its anchored roots, each of its space at its window.
    pub anchors: Vec<RootRead>,
    /// The statements it has accepted, each with the time its entry expires
    /// (`crate::seen_expiry`, `u64::MAX` never).
    pub seen: Vec<(StatementId, u64)>,
}

impl Policy {
    /// A venue of id `venue` at time `now_ms` accepting `formats`, of no
    /// space, root or statement yet.
    pub fn new(venue: VenueId, now_ms: u64, formats: &[u32]) -> Self {
        Self {
            venue,
            now_ms,
            formats: formats.to_vec(),
            spaces: Vec::new(),
            anchors: Vec::new(),
            seen: Vec::new(),
        }
    }

    /// The registered space `id`.
    pub fn space(&self, id: &SpaceId) -> Option<&Space> {
        self.spaces.iter().find(|space| space.id == *id)
    }

    /// `statement`, accepted, recorded under the `Seen` rule: its entry
    /// expires with its newest root, or never when it has none.
    pub fn record(&mut self, statement: &Statement) {
        let expiry = self
            .space(&statement.space)
            .map_or(u64::MAX, |space| seen_expiry(statement, &space.clock));
        self.seen.push((statement.id(), expiry));
    }

    /// The venue's time moved to `now_ms`, and what it may then drop
    /// dropped: the anchors past [`MAX_ROOT_AGE_MS`] and the `Seen` entries
    /// past their expiry.
    pub fn advance(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        let spaces = &self.spaces;
        self.anchors.retain(|root| {
            spaces
                .iter()
                .find(|space| space.id == root.space)
                .is_some_and(|space| fresh(&space.clock, root.window, now_ms))
        });
        self.seen.retain(|&(_, expiry)| now_ms <= expiry);
    }
}

/// Whether window `window`'s root is not past [`MAX_ROOT_AGE_MS`] at
/// `now_ms`: `now − B_w ≤ MaxRootAge`.
fn fresh(clock: &WindowClock, window: u64, now_ms: u64) -> bool {
    clock
        .boundary(window)
        .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
        .is_some_and(|last| now_ms <= last)
}

impl Venue for Policy {
    fn id(&self) -> VenueId {
        self.venue
    }

    fn accepts(&self, format: u32) -> bool {
        self.formats.contains(&format)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.space(&root.space).is_some_and(|space| {
            space.range.contains(root.window)
                && fresh(&space.clock, root.window, self.now_ms)
                && self.anchors.contains(root)
        })
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.seen.iter().any(|(seen, _)| seen == id)
    }
}

/// A judgement's input, but its proof: what the venue pinned, its state and
/// the statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub pin: Pin,
    pub policy: Policy,
    pub statement: Statement,
}

impl Input {
    /// Its encoding: the pin (the program id's 32 bytes, then 1 if it is
    /// venue-bound, else 0); the venue's id and its time (8 bytes,
    /// little-endian); the formats, the spaces (each its id, its clock, its
    /// range's start, then 0, or 1 and its end), the anchors and the seen
    /// entries (each its id and its expiry), each a compact count and its
    /// items; then the statement's canonical encoding. Integers are
    /// little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.pin.program.to_bytes());
        out.push(u8::from(self.pin.venue_bound));
        let policy = &self.policy;
        out.extend_from_slice(&policy.venue.0);
        out.extend_from_slice(&policy.now_ms.to_le_bytes());
        codec::compact(&mut out, policy.formats.len() as u64);
        for format in &policy.formats {
            out.extend_from_slice(&format.to_le_bytes());
        }
        codec::compact(&mut out, policy.spaces.len() as u64);
        for space in &policy.spaces {
            space.encode_to(&mut out);
        }
        codec::compact(&mut out, policy.anchors.len() as u64);
        for root in &policy.anchors {
            root.encode_to(&mut out);
        }
        codec::compact(&mut out, policy.seen.len() as u64);
        for (id, expiry) in &policy.seen {
            out.extend_from_slice(&id.0);
            out.extend_from_slice(&expiry.to_le_bytes());
        }
        self.statement.encode_to(&mut out);
        out
    }

    /// The input at the start of `bytes`, and the bytes it takes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut reader = Reader::new(bytes);
        let program = decode_program(&mut reader)?;
        let venue_bound = flag(&mut reader)?;
        let venue = VenueId(reader.array()?);
        let now_ms = reader.u64()?;
        let count = reader.count(4)?;
        let formats = (0..count).map(|_| reader.u32()).collect::<Result<_, _>>()?;
        let count = reader.count(Space::MIN_BYTES)?;
        let spaces = (0..count)
            .map(|_| Space::decode_from(&mut reader))
            .collect::<Result<_, _>>()?;
        let count = reader.count(RootRead::BYTES)?;
        let anchors = (0..count)
            .map(|_| RootRead::decode_from(&mut reader))
            .collect::<Result<_, _>>()?;
        let count = reader.count(32 + 8)?;
        let seen = (0..count)
            .map(|_| Ok((StatementId(reader.array()?), reader.u64()?)))
            .collect::<Result<_, DecodeError>>()?;
        let statement = Statement::decode_from(&mut reader)?;
        let input = Self {
            pin: Pin {
                program,
                venue_bound,
            },
            policy: Policy {
                venue,
                now_ms,
                formats,
                spaces,
                anchors,
                seen,
            },
            statement,
        };
        Ok((input, reader.used()))
    }

    /// [`admit`] on this input.
    pub fn admit(&self) -> Result<Admitted, Refusal> {
        admit(&self.policy, &self.pin, &self.statement)
    }

    /// [`judge`] on this input and `proof`.
    pub fn judge(&self, proof: &[u8]) -> Result<StatementId, Refusal> {
        judge(&self.policy, &self.pin, &self.statement, proof)
    }
}

/// A flag byte: 0 or 1, any other refused.
fn flag(reader: &mut Reader<'_>) -> Result<bool, DecodeError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::Noncanonical),
    }
}

/// The judgement of `bytes`, an [`Input`]'s encoding then the proof's bytes;
/// [`Refusal::Statement`] when the input does not decode.
pub fn judge_bytes(bytes: &[u8]) -> Result<StatementId, Refusal> {
    let (input, used) = Input::decode_prefix(bytes).map_err(Refusal::Statement)?;
    input.judge(&bytes[used..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_final_verifier::masked::FORMAT;

    const VENUE: VenueId = VenueId([0x7e; 32]);
    /// The time the fixtures' venue judges at: window 42's boundary.
    const NOW: u64 = 43 * 600_000;

    /// A venue that pins the statement's program, venue-bound, accepts
    /// format 39, registers its space from window 40 and anchors its roots,
    /// at window 42's boundary; and the statement, its `public_args` the
    /// venue's id and a nonce.
    fn input() -> Input {
        let mut statement = crate::tests::statement();
        statement.public_args = [&VENUE.0[..], b"nonce 7"].concat();
        let mut policy = Policy::new(VENUE, NOW, &[FORMAT]);
        policy.spaces.push(Space {
            id: statement.space,
            clock: WindowClock::DEFAULT,
            range: Range {
                from: 40,
                until: None,
            },
        });
        policy.anchors = statement.roots.clone();
        policy.seen.push((StatementId([9; 32]), u64::MAX));
        Input {
            pin: Pin {
                program: statement.program,
                venue_bound: true,
            },
            policy,
            statement,
        }
    }

    /// `input` changed by `change`, judged with a proof that does not
    /// decode: its code.
    fn refusal(change: impl FnOnce(&mut Input)) -> u32 {
        let mut changed = input();
        change(&mut changed);
        let mut bytes = changed.encode();
        bytes.extend_from_slice(&[39, 1, 2]);
        judge_bytes(&bytes).unwrap_err().code()
    }

    /// An input round-trips, its flags canonical; a short one is refused.
    #[test]
    fn an_input_round_trips() {
        let mut input = input();
        input.policy.spaces[0].range.until = Some(77);
        let bytes = input.encode();
        assert_eq!(
            Input::decode_prefix(&bytes),
            Ok((input.clone(), bytes.len()))
        );
        let mut flag = bytes.clone();
        flag[32] = 2;
        assert_eq!(Input::decode_prefix(&flag), Err(DecodeError::Noncanonical));
        assert_eq!(judge_bytes(&bytes[..40]).unwrap_err().code(), 1);
    }

    /// A venue's refusals before the proof each by its own check, in pin
    /// F's order; the proof refused when they pass.
    #[test]
    fn a_venue_refuses_by_its_checks() {
        assert_eq!(refusal(|_| {}), 0x100 | 1, "undecodable proof bytes");
        assert_eq!(refusal(|i| i.statement.format = 30), 2);
        assert_eq!(refusal(|i| i.policy.formats.clear()), 2);
        // A format the venue accepts but this build does not link.
        assert_eq!(
            refusal(|i| {
                i.statement.format = 40;
                i.policy.formats.push(40);
            }),
            2
        );
        assert_eq!(refusal(|i| i.pin.program.0[0] += 1), 3);
        assert_eq!(refusal(|i| i.statement.roots[1].space.0[0] ^= 1), 4);
        assert_eq!(
            refusal(|i| {
                i.policy.anchors.remove(0);
            }),
            5
        );
        assert_eq!(
            refusal(|i| {
                let id = i.statement.id();
                i.policy.seen.push((id, u64::MAX));
            }),
            6
        );
        // A rootless statement needs no anchor, and belongs to no space:
        // one claiming a space is refused, since nothing binds it and each
        // space would give the same proof another id.
        assert_eq!(
            refusal(|i| {
                i.statement.roots.clear();
                i.policy.anchors.clear();
            }),
            4
        );
        assert_eq!(
            refusal(|i| {
                i.statement.roots.clear();
                i.statement.space = SpaceId::NONE;
            }),
            0x100 | 1
        );
        // A rooted statement claiming no space, its roots of none too,
        // anchored and registered: refused as a claim, before any anchor is
        // looked up.
        assert_eq!(
            refusal(|i| {
                i.statement.space = SpaceId::NONE;
                for root in &mut i.statement.roots {
                    root.space = SpaceId::NONE;
                }
                i.policy.spaces[0].id = SpaceId::NONE;
                i.policy.anchors = i.statement.roots.clone();
            }),
            4
        );
    }

    /// The venue of a venue-bound program's statement: its `public_args`
    /// start with the venue's id, or it is refused (7) before the space;
    /// a program that is not venue-bound is judged at any venue.
    #[test]
    fn a_venue_bound_statement_is_one_venues() {
        assert_eq!(refusal(|i| i.policy.venue.0[31] ^= 1), 7);
        assert_eq!(refusal(|i| i.statement.public_args[0] ^= 1), 7);
        assert_eq!(refusal(|i| i.statement.public_args.truncate(31)), 7);
        assert_eq!(refusal(|i| i.statement.public_args.clear()), 7);
        assert_eq!(
            refusal(|i| {
                i.policy.venue.0[31] ^= 1;
                i.statement.roots[1].space.0[0] ^= 1;
            }),
            7,
            "the venue before the space"
        );
        assert_eq!(
            refusal(|i| {
                i.policy.venue.0[31] ^= 1;
                i.pin.program.0[0] += 1;
            }),
            3,
            "the program before the venue"
        );
        assert_eq!(
            refusal(|i| {
                i.pin.venue_bound = false;
                i.policy.venue.0[31] ^= 1;
            }),
            0x100 | 1
        );
        // Exactly the venue's 32 bytes: no nonce after them.
        assert_eq!(refusal(|i| i.statement.public_args.truncate(32)), 0x100 | 1);
    }

    /// A root is anchored only within its space's range at the venue, from
    /// its start to its migration away (exclusive), of a registered space,
    /// and not past `MaxRootAge` by the venue's time.
    #[test]
    fn a_root_outside_its_spaces_range_or_age_is_unanchored() {
        // The roots are at windows 41 and 42.
        assert_eq!(
            refusal(|i| i.policy.spaces[0].range = Range {
                from: 42,
                until: None
            }),
            5
        );
        assert_eq!(
            refusal(|i| i.policy.spaces[0].range = Range {
                from: 41,
                until: Some(42)
            }),
            5
        );
        assert_eq!(
            refusal(|i| i.policy.spaces[0].range = Range {
                from: 41,
                until: Some(43)
            }),
            0x100 | 1
        );
        assert_eq!(refusal(|i| i.policy.spaces.clear()), 5);
        // Window 41's boundary is 42 × 600,000 ms.
        let last = 42 * 600_000 + MAX_ROOT_AGE_MS;
        assert_eq!(refusal(|i| i.policy.now_ms = last), 0x100 | 1);
        assert_eq!(refusal(|i| i.policy.now_ms = last + 1), 5);
    }

    /// Pin F's `Seen` rule on the model: past `MaxRootAge`, a rooted
    /// statement's entry and its anchors are dropped, and its replay is
    /// refused as unanchored; a rootless statement's entry is kept, and its
    /// replay refused as a repeat.
    #[test]
    fn past_max_root_age_a_rooted_replay_is_unanchored_and_a_rootless_one_repeated() {
        let mut rooted = input();
        rooted.policy.record(&rooted.statement);
        let mut rootless = input();
        rootless.statement.space = SpaceId::NONE;
        rootless.statement.roots.clear();
        rootless.policy.record(&rootless.statement);
        let code = |input: &Input| {
            let mut bytes = input.encode();
            bytes.extend_from_slice(&[39]);
            judge_bytes(&bytes).unwrap_err().code()
        };
        assert_eq!(code(&rooted), 6);
        assert_eq!(code(&rootless), 6);

        let past = 43 * 600_000 + MAX_ROOT_AGE_MS + 1;
        rooted.policy.advance(past);
        rootless.policy.advance(past);
        assert_eq!(rooted.policy.seen.len(), 1, "the earlier entry alone");
        assert_eq!(rootless.policy.seen.len(), 2);
        assert!(rooted.policy.anchors.is_empty());
        assert_eq!(code(&rooted), 5);
        assert_eq!(code(&rootless), 6);
        assert!(rootless.policy.seen(&rootless.statement.id()));
    }
}
