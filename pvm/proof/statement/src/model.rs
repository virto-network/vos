//! A venue modelled as plain data, which the golden fixtures are judged
//! against: the formats it accepts, its anchored roots and the statements
//! it has accepted, as lists ([`Policy`]); and a judgement's input as one
//! byte string ([`Input`], then the proof), which the harnesses hand every
//! venue alike, natively, in Wasm and on the JAM-only host. A real venue,
//! Kreivo's pallet, keeps the same three checks over its storage and pins
//! the program id by the kernel its call names.

use alloc::vec::Vec;

use crate::{
    Admitted, DecodeError, ProgramId, Refusal, RootRead, Statement, StatementId, Venue, admit,
    decode_program, judge,
};
use vos_anchor::codec::{self, Reader};

/// A venue's state as lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The formats it accepts.
    pub formats: Vec<u32>,
    /// Its anchored roots, each of its space at its window.
    pub anchors: Vec<RootRead>,
    /// The statements it has accepted.
    pub seen: Vec<StatementId>,
}

impl Venue for Policy {
    fn accepts(&self, format: u32) -> bool {
        self.formats.contains(&format)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.anchors.contains(root)
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.seen.contains(id)
    }
}

/// A judgement's input, but its proof: the program id the venue pinned, its
/// state and the statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub program: ProgramId,
    pub policy: Policy,
    pub statement: Statement,
}

impl Input {
    /// Its encoding: the program id's 32 bytes; the formats, the anchors and
    /// the seen ids, each a compact count and its items; then the
    /// statement's canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.program.to_bytes());
        codec::compact(&mut out, self.policy.formats.len() as u64);
        for format in &self.policy.formats {
            out.extend_from_slice(&format.to_le_bytes());
        }
        codec::compact(&mut out, self.policy.anchors.len() as u64);
        for root in &self.policy.anchors {
            root.encode_to(&mut out);
        }
        codec::compact(&mut out, self.policy.seen.len() as u64);
        for id in &self.policy.seen {
            out.extend_from_slice(&id.0);
        }
        self.statement.encode_to(&mut out);
        out
    }

    /// The input at the start of `bytes`, and the bytes it takes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut reader = Reader::new(bytes);
        let program = decode_program(&mut reader)?;
        let count = reader.count(4)?;
        let formats = (0..count).map(|_| reader.u32()).collect::<Result<_, _>>()?;
        let count = reader.count(RootRead::BYTES)?;
        let anchors = (0..count)
            .map(|_| RootRead::decode_from(&mut reader))
            .collect::<Result<_, _>>()?;
        let count = reader.count(32)?;
        let seen = (0..count)
            .map(|_| reader.array().map(StatementId))
            .collect::<Result<_, _>>()?;
        let statement = Statement::decode_from(&mut reader)?;
        let input = Self {
            program,
            policy: Policy {
                formats,
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
    input.judge(&bytes[used..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FORMAT;

    /// An input round-trips; a venue's refusals before the proof each by
    /// its own check, the proof refused when they pass.
    #[test]
    fn a_venue_refuses_by_its_checks() {
        let statement = crate::tests::statement();
        let policy = Policy {
            formats: alloc::vec![FORMAT],
            anchors: statement.roots.clone(),
            seen: alloc::vec![StatementId([9; 32])],
        };
        let input = Input {
            program: statement.program,
            policy,
            statement,
        };
        let bytes = input.encode();
        assert_eq!(
            Input::decode_prefix(&bytes),
            Ok((input.clone(), bytes.len()))
        );

        let refusal = |change: fn(&mut Input)| {
            let mut changed = input.clone();
            change(&mut changed);
            let mut bytes = changed.encode();
            bytes.extend_from_slice(&[28, 1, 2]);
            judge_bytes(&bytes).unwrap_err().code()
        };
        assert_eq!(refusal(|_| {}), 0x100 | 1, "undecodable proof bytes");
        assert_eq!(refusal(|i| i.statement.format = 30), 2);
        assert_eq!(refusal(|i| i.policy.formats.clear()), 2);
        assert_eq!(refusal(|i| i.program.0[0] += 1), 3);
        assert_eq!(refusal(|i| i.statement.roots[1].space.0[0] ^= 1), 4);
        assert_eq!(
            refusal(|i| {
                i.policy.anchors.remove(0);
            }),
            5
        );
        assert_eq!(refusal(|i| i.policy.seen.push(i.statement.id())), 6);
        // A venue in a transition accepts a second final format; the run
        // accepted under it is the same statement under this one.
        assert_eq!(
            refusal(|i| {
                let mut other = i.statement.clone();
                other.format = FORMAT + 10;
                i.policy.formats.push(other.format);
                i.policy.seen.push(other.id());
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
                i.statement.space = crate::SpaceId::NONE;
            }),
            0x100 | 1
        );
        // A rooted statement claiming no space, its roots of none too,
        // anchored: refused as a claim, before any anchor is looked up.
        assert_eq!(
            refusal(|i| {
                i.statement.space = crate::SpaceId::NONE;
                for root in &mut i.statement.roots {
                    root.space = crate::SpaceId::NONE;
                }
                i.policy.anchors = i.statement.roots.clone();
            }),
            4
        );
        assert_eq!(judge_bytes(&bytes[..40]).unwrap_err().code(), 1);
    }
}
