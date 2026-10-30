//! A venue modelled as plain data, which the golden fixtures are judged
//! against: its time, the formats it accepts, its registered spaces, its
//! anchored roots and its `Seen` entries, as lists ([`Policy`]); and a
//! judgement's input as one byte string ([`Input`], then the proof), which
//! the harnesses hand every venue alike, natively, in Wasm and on the
//! JAM-only host. What is anchored is `vos_anchor::venue`'s rule over the
//! lists. A real venue, Kreivo's pallet, keeps the same checks over its
//! storage and pins the program by the kernel its call names.

use alloc::vec::Vec;

use crate::{
    Admitted, DecodeError, ProgramId, Refusal, RootKind, RootRead, SpaceId, Statement, StatementId,
    Venue, WindowClock, admit, judge, seen_expiry,
};
use vos_anchor::codec::{self, Reader};
use vos_anchor::venue::{self as rules, Held, Roots, Status};

/// A space registered at the venue, active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    pub id: SpaceId,
    /// Its clock, from its genesis.
    pub clock: WindowClock,
}

impl Space {
    /// The bytes of its encoding.
    const BYTES: usize = 32 + WindowClock::BYTES;

    /// Its encoding: its id, then its clock.
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.0);
        self.clock.encode_to(out);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            id: SpaceId(reader.array()?),
            clock: WindowClock::decode_from(reader)?,
        })
    }
}

/// A venue's state as lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Its time: milliseconds since the Unix epoch, by its own clock.
    pub now_ms: u64,
    /// The formats it accepts.
    pub formats: Vec<u32>,
    /// Its registered spaces.
    pub spaces: Vec<Space>,
    /// Its anchored roots, each of its space at its window.
    pub anchors: Vec<RootRead>,
    /// The statements it has accepted, each with the time its entry expires
    /// (`crate::seen_expiry`).
    pub seen: Vec<(StatementId, u64)>,
}

impl Policy {
    /// A venue at time `now_ms` accepting `formats`, of no space, root or
    /// statement yet.
    pub fn new(now_ms: u64, formats: &[u32]) -> Self {
        Self {
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
    /// expires with its newest root.
    pub fn record(&mut self, statement: &Statement) {
        let expiry = self
            .space(&statement.space)
            .map_or(u64::MAX, |space| seen_expiry(statement, &space.clock));
        self.seen.push((statement.id(), expiry));
    }

    /// The venue's time moved to `now_ms`, and what it may then drop
    /// dropped: the anchors past `MaxRootAge` and the `Seen` entries past
    /// their expiry.
    pub fn advance(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        let spaces = &self.spaces;
        self.anchors.retain(|root| {
            spaces
                .iter()
                .find(|space| space.id == root.space)
                .is_some_and(|space| rules::fresh(&space.clock, root.window, now_ms))
        });
        self.seen.retain(|&(_, expiry)| now_ms <= expiry);
    }
}

impl Roots for Policy {
    fn now(&self) -> u64 {
        self.now_ms
    }

    /// A policy lists its spaces' clocks alone: each reads as active from
    /// window 0, which is all `anchored` asks of a space it lists (its
    /// start and an ended or blocked status matter to the anchor rule and
    /// to `anchored` at a venue, which keeps them).
    fn space(&self, space: &SpaceId) -> Option<rules::Space> {
        Policy::space(self, space).map(|space| rules::Space {
            clock: space.clock,
            start: 0,
            status: Status::Active,
        })
    }

    fn held(&self, space: &SpaceId, kind: RootKind, window: u64) -> Option<Held> {
        self.anchors
            .iter()
            .find(|root| root.space == *space && root.kind == kind && root.window == window)
            .map(|root| Held {
                root: root.root,
                signer: [0; 32],
            })
    }
}

impl Venue for Policy {
    fn accepts(&self, format: u32) -> bool {
        self.formats.contains(&format)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        rules::anchored(self, root)
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.seen.iter().any(|(seen, _)| seen == id)
    }
}

/// A judgement's input, but its proof: the program id the venue pinned,
/// its state and the statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub program: ProgramId,
    pub policy: Policy,
    pub statement: Statement,
}

impl Input {
    /// Its encoding: the pinned program id's 32 bytes; the venue's time (8
    /// bytes, little-endian); the formats, the spaces (each its id and its
    /// clock), the anchors and the seen entries (each its id and its
    /// expiry), each a compact count and its items; then the statement's
    /// canonical encoding. Integers are little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.program.to_bytes());
        let policy = &self.policy;
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
        let program = ProgramId::decode_from(&mut reader)?;
        let now_ms = reader.u64()?;
        let count = reader.count(4)?;
        let formats = (0..count).map(|_| reader.u32()).collect::<Result<_, _>>()?;
        let count = reader.count(Space::BYTES)?;
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
            program,
            policy: Policy {
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
        admit(&self.policy, &self.program, &self.statement)
    }

    /// [`judge`] on this input and `proof`.
    pub fn judge(&self, proof: &[u8]) -> Result<StatementId, Refusal> {
        judge(&self.policy, &self.program, &self.statement, proof)
    }
}

/// The judgement of `bytes`, an [`Input`]'s encoding then the proof's bytes;
/// [`Refusal::Statement`] when the input does not decode.
pub fn judge_bytes(bytes: &[u8]) -> Result<StatementId, Refusal> {
    let (input, used) = Input::decode_prefix(bytes).map_err(Refusal::Statement)?;
    let proof = bytes
        .get(used..)
        .ok_or(Refusal::Statement(DecodeError::Short))?;
    input.judge(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_anchor::MAX_ROOT_AGE_MS;
    use vos_pvm_final_verifier::masked::FORMAT;

    /// The time the fixtures' venue judges at: window 42's boundary.
    const NOW: u64 = 43 * 600_000;

    /// A venue that pins the statement's program, accepts
    /// `format::MASKED_WRAP`, registers its space and anchors its roots, at
    /// window 42's boundary; and the statement.
    fn input() -> Input {
        let statement = crate::tests::statement();
        let mut policy = Policy::new(NOW, &[FORMAT]);
        policy.spaces.push(Space {
            id: statement.space,
            clock: WindowClock::DEFAULT,
        });
        policy.anchors = statement.roots.clone();
        policy.seen.push((StatementId([9; 32]), u64::MAX));
        Input {
            program: statement.program,
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

    /// An input round-trips; a short one is refused.
    #[test]
    fn an_input_round_trips() {
        let input = input();
        let bytes = input.encode();
        assert_eq!(
            Input::decode_prefix(&bytes),
            Ok((input.clone(), bytes.len()))
        );
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
        assert_eq!(refusal(|i| i.program.0[0] += 1), 3);
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
        // A statement of no root is refused, its space claimed or not: a
        // venue judges rooted statements alone.
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
            4
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

    /// A root is anchored only of a registered space, held at its window,
    /// and not past `MaxRootAge` by the venue's time.
    #[test]
    fn a_root_of_no_space_or_past_its_age_is_unanchored() {
        assert_eq!(refusal(|i| i.policy.spaces.clear()), 5);
        assert_eq!(refusal(|i| i.policy.anchors[1].window = 43), 5);
        // Window 41's boundary is 42 × 600,000 ms.
        let last = 42 * 600_000 + MAX_ROOT_AGE_MS;
        assert_eq!(refusal(|i| i.policy.now_ms = last), 0x100 | 1);
        assert_eq!(refusal(|i| i.policy.now_ms = last + 1), 5);
    }

    /// Pin F's `Seen` rule on the model: past `MaxRootAge`, a statement's
    /// entry and its anchors are dropped, and its replay is refused as
    /// unanchored.
    #[test]
    fn past_max_root_age_a_replay_is_unanchored() {
        let mut rooted = input();
        rooted.policy.record(&rooted.statement);
        let code = |input: &Input| {
            let mut bytes = input.encode();
            bytes.extend_from_slice(&[39]);
            judge_bytes(&bytes).unwrap_err().code()
        };
        assert_eq!(code(&rooted), 6);
        let past = 43 * 600_000 + MAX_ROOT_AGE_MS + 1;
        rooted.policy.advance(past);
        assert_eq!(rooted.policy.seen.len(), 1, "the earlier entry alone");
        assert!(rooted.policy.anchors.is_empty());
        assert_eq!(code(&rooted), 5);
    }
}
