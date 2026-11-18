//! The service's storage: its keys and its records, which accumulate
//! writes and a client reads (PolkaJam's `serviceValue`).
//!
//! | key | value |
//! |---|---|
//! | `0x01 ‖ space` | [`SpaceRecord`]: its clock, controller, anchor keys, first window, last window anchored, whether it ended, its controls' nonce; never dropped |
//! | `0x02 ‖ space ‖ kind ‖ w (8, BE)` | [`AnchorRecord`]: the root anchored and its signer |
//! | `0x03 ‖ statement id` | a `Seen` entry: the venue time it expires at (8, LE) |
//! | `0x04 ‖ space ‖ kind ‖ w (8, BE)` | [`Evidence`]: the root held and the other, each with its signer; never dropped |
//! | `0x05 ‖ outcome id` | [`Outcome`]: what became of an item, by [`outcome_id`]: its package's and its payload's hashes |
//! | `0x06 ‖ bucket (8, BE)` | the count of rows queued to drop in the hour `bucket` (4, LE) |
//! | `0x07 ‖ bucket (8, BE) ‖ i (4, BE)` | the key of a row to drop once the hour `bucket` is past |
//! | `0x08` | the pruning's cursor: the bucket (8) and the index (4) it is at |
//! | `0x09` | the gas the last accumulate took, by its own count (8, LE) |
//!
//! A row is the service's own: one that does not decode is a fault, and
//! the invocation traps ([`Storage::corrupt`]), so accumulate reverts
//! rather than read it as absent.

use alloc::vec::Vec;

use vos_statement::vos_anchor::codec::{self, Reader};
use vos_statement::vos_anchor::{RootKind, SpaceId, WindowClock};
use vos_statement::{DecodeError, StatementId};

use crate::item::Kind;

/// A service's storage, as accumulate's `read` and `write` reach it.
pub trait Storage {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    /// Set the value of `key`, or delete it (`None`).
    fn write(&mut self, key: &[u8], value: Option<&[u8]>);
    /// A row at `key` that does not decode: the invocation stops, every
    /// write of it reverted.
    fn corrupt(&mut self, key: &[u8]) -> !;
}

/// Storage held in memory, by key: a client's copy, a test's.
impl Storage for alloc::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        match value {
            Some(value) => self.insert(key.to_vec(), value.to_vec()),
            None => self.remove(key),
        };
    }

    #[allow(
        clippy::panic,
        reason = "a copy of the service's storage holds the rows it wrote: one that does not \
                  decode is the copy's fault, and the caller's invocation stops as the \
                  service's does"
    )]
    fn corrupt(&mut self, key: &[u8]) -> ! {
        panic!("a row that does not decode at {key:02x?}")
    }
}

/// The row at `key`, decoded by `decode`; the invocation stopped when it
/// does not decode.
fn row<T>(
    storage: &mut impl Storage,
    key: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
) -> Option<T> {
    let bytes = storage.read(key)?;
    match decode(&bytes) {
        Ok(value) => Some(value),
        Err(_) => storage.corrupt(key),
    }
}

/// The storage's keys.
pub mod keys {
    use alloc::vec::Vec;

    use vos_statement::StatementId;
    use vos_statement::vos_anchor::{RootKind, SpaceId};

    /// A key's first byte: what its row is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Prefix {
        Space = 0x01,
        Anchor = 0x02,
        Seen = 0x03,
        Evidence = 0x04,
        Outcome = 0x05,
        Bucket = 0x06,
        Queued = 0x07,
        Cursor = 0x08,
        Gas = 0x09,
    }

    /// The pruning's cursor.
    pub const CURSOR: &[u8] = &[Prefix::Cursor as u8];
    /// The gas the last accumulate took.
    pub const GAS: &[u8] = &[Prefix::Gas as u8];

    pub fn space(space: &SpaceId) -> Vec<u8> {
        [&[Prefix::Space as u8][..], &space.0].concat()
    }

    /// A row of `space`'s root of `kind` at `window`, under `prefix`.
    fn at_window(prefix: Prefix, space: &SpaceId, kind: RootKind, window: u64) -> Vec<u8> {
        [
            &[prefix as u8][..],
            &space.0,
            &[kind as u8],
            &window.to_be_bytes(),
        ]
        .concat()
    }

    pub fn anchor(space: &SpaceId, kind: RootKind, window: u64) -> Vec<u8> {
        at_window(Prefix::Anchor, space, kind, window)
    }

    pub fn seen(id: &StatementId) -> Vec<u8> {
        [&[Prefix::Seen as u8][..], &id.0].concat()
    }

    pub fn evidence(space: &SpaceId, kind: RootKind, window: u64) -> Vec<u8> {
        at_window(Prefix::Evidence, space, kind, window)
    }

    /// An item's outcome, by [`super::outcome_id`].
    pub fn outcome(id: &[u8; 32]) -> Vec<u8> {
        [&[Prefix::Outcome as u8][..], id].concat()
    }

    pub fn bucket(bucket: u64) -> Vec<u8> {
        [&[Prefix::Bucket as u8][..], &bucket.to_be_bytes()].concat()
    }

    pub fn queued(bucket: u64, index: u32) -> Vec<u8> {
        [
            &[Prefix::Queued as u8][..],
            &bucket.to_be_bytes(),
            &index.to_be_bytes(),
        ]
        .concat()
    }
}

/// A space the service registered: never dropped, so an ended one stays
/// recorded and its registration is never taken again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceRecord {
    pub clock: WindowClock,
    /// The ed25519 key that controls it.
    pub controller: [u8; 32],
    /// Its anchor keys: its founding keys, then those its controller
    /// added.
    pub keys: Vec<[u8; 32]>,
    /// The first window it anchors here: the service's next at its
    /// registration.
    pub start: u64,
    /// The last window anchored, which a later anchor must pass.
    pub last: Option<u64>,
    /// It equivocated: its roots are not anchored, its anchors refused, for
    /// good.
    pub ended: bool,
    /// Its controls taken: the nonce its next one names.
    pub nonce: u64,
}

impl SpaceRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.clock.encode_to(&mut out);
        out.extend_from_slice(&self.controller);
        out.extend_from_slice(&self.start.to_le_bytes());
        codec::option_u64(&mut out, self.last);
        codec::flag(&mut out, self.ended);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        codec::compact(&mut out, self.keys.len() as u64);
        for key in &self.keys {
            out.extend_from_slice(key);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let clock = WindowClock::decode_from(&mut reader)?;
        let controller = reader.array()?;
        let start = reader.u64()?;
        let last = reader.option_u64()?;
        let ended = reader.flag()?;
        let nonce = reader.u64()?;
        let count = reader.count(32)?;
        let keys = (0..count)
            .map(|_| reader.array())
            .collect::<Result<_, _>>()?;
        reader.finish()?;
        Ok(Self {
            clock,
            controller,
            keys,
            start,
            last,
            ended,
            nonce,
        })
    }
}

/// An anchored root, with the key that signed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub root: [u8; 32],
    pub signer: [u8; 32],
}

impl AnchorRecord {
    /// The bytes of its encoding: the root, then the signer.
    pub const BYTES: usize = 32 + 32;

    pub fn encode(&self) -> Vec<u8> {
        [&self.root[..], &self.signer].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let record = Self {
            root: reader.array()?,
            signer: reader.array()?,
        };
        reader.finish()?;
        Ok(record)
    }
}

/// A space's equivocation at a window: the root held and the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub held: AnchorRecord,
    pub other: AnchorRecord,
}

impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        [self.held.encode(), self.other.encode()].concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (held, other) = bytes
            .split_at_checked(AnchorRecord::BYTES)
            .ok_or(DecodeError::Short)?;
        Ok(Self {
            held: AnchorRecord::decode(held)?,
            other: AnchorRecord::decode(other)?,
        })
    }
}

/// What became of an item: when accumulate took it, the kind of item, its
/// code (its kind's: `vos_statement::code`'s for a statement), what it is
/// of (the space, or the statement's id) and the gas its refine took by its
/// own count (0 when refine failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The venue's time, ms since the Unix epoch.
    pub time: u64,
    /// The item's kind; none when it did not decode, or refine failed
    /// (`code` then [`Outcome::FAILED`] past the work error's). Its byte,
    /// `u8::MAX` for none ([`Kind::encode_option`]).
    pub kind: Option<Kind>,
    pub code: u32,
    pub subject: [u8; 32],
    pub refine_gas: u64,
}

impl Outcome {
    pub const BYTES: usize = 8 + 1 + 4 + 32 + 8;
    /// A failed refine's code: its work error's (1 out of gas, 2 a panic,
    /// …) past this.
    pub const FAILED: u32 = 0x1000;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.push(Kind::encode_option(self.kind));
        out.extend_from_slice(&self.code.to_le_bytes());
        out.extend_from_slice(&self.subject);
        out.extend_from_slice(&self.refine_gas.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let outcome = Self {
            time: reader.u64()?,
            kind: Kind::decode_option(reader.u8()?)?,
            code: reader.u32()?,
            subject: reader.array()?,
            refine_gas: reader.u64()?,
        };
        reader.finish()?;
        Ok(outcome)
    }
}

/// A registered space.
pub fn space(storage: &mut impl Storage, space: &SpaceId) -> Option<SpaceRecord> {
    row(storage, &keys::space(space), SpaceRecord::decode)
}

/// The root anchored for `space` of `kind` at `window`.
pub fn anchor(
    storage: &mut impl Storage,
    space: &SpaceId,
    kind: RootKind,
    window: u64,
) -> Option<AnchorRecord> {
    row(
        storage,
        &keys::anchor(space, kind, window),
        AnchorRecord::decode,
    )
}

/// The expiry of statement `id`'s `Seen` entry, if it has one.
pub fn seen(storage: &mut impl Storage, id: &StatementId) -> Option<u64> {
    row(storage, &keys::seen(id), |bytes| {
        let mut reader = Reader::new(bytes);
        let expiry = reader.u64()?;
        reader.finish()?;
        Ok(expiry)
    })
}

/// An item's outcome id: `BLAKE2b-256(package hash ‖ payload hash)`, so
/// its own package's outcome, not a later package's of the same payload.
pub fn outcome_id(package_hash: &[u8; 32], payload_hash: &[u8; 32]) -> [u8; 32] {
    vos_statement::blake2b_256(&[package_hash, payload_hash])
}

/// The outcome of the item of id `id` ([`outcome_id`]).
pub fn outcome(storage: &mut impl Storage, id: &[u8; 32]) -> Option<Outcome> {
    row(storage, &keys::outcome(id), Outcome::decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn every_record_decodes_from_its_encoding() {
        let space = SpaceRecord {
            clock: WindowClock::DEFAULT,
            controller: [1; 32],
            keys: vec![[2; 32], [3; 32]],
            start: 4,
            last: Some(7),
            ended: true,
            nonce: 3,
        };
        assert_eq!(SpaceRecord::decode(&space.encode()), Ok(space.clone()));
        let open = SpaceRecord {
            last: None,
            ended: false,
            keys: Vec::new(),
            ..space
        };
        assert_eq!(SpaceRecord::decode(&open.encode()), Ok(open));
        let evidence = Evidence {
            held: AnchorRecord {
                root: [5; 32],
                signer: [6; 32],
            },
            other: AnchorRecord {
                root: [7; 32],
                signer: [8; 32],
            },
        };
        assert_eq!(Evidence::decode(&evidence.encode()), Ok(evidence));
        let outcome = Outcome {
            time: 1,
            kind: Some(Kind::Submit),
            code: 0x108,
            subject: [9; 32],
            refine_gas: 118_000_000,
        };
        assert_eq!(outcome.encode().len(), Outcome::BYTES);
        assert_eq!(Outcome::decode(&outcome.encode()), Ok(outcome));
        let failed = Outcome {
            kind: None,
            ..outcome
        };
        assert_eq!(Outcome::decode(&failed.encode()), Ok(failed));
    }
}
