//! A space as a venue knows it (`spaces-pallet.md` §6.1): its
//! identity, the clock that numbers its windows, the roots it states of a
//! window and their anchors, with the digests a venue checks signatures
//! over. The venue verifies the signatures (ed25519); this crate gives the
//! bytes they sign.
//!
//! - **A space's id** is the hash of its genesis ([`SpaceGenesis`]): its
//!   founding nodes' keys, its window clock, its founder's time and a nonce.
//!   The id is self-certifying, so a venue registering a space takes the
//!   genesis and computes the id: it learns the clock and the founding keys
//!   from the hash. The clock is frozen: a space with another clock is
//!   another space.
//! - **Windows:** [`WindowClock`] numbers time in windows from its origin,
//!   `w = ⌊(t − origin_ms) / length_ms⌋`, none before the origin; window w
//!   ends at its boundary `B_w = origin_ms + (w+1)·length_ms`.
//! - **The space root** of a window, `S_w` ([`space_root`]), binds the space,
//!   the window and its representative's agent root at its cut.
//! - **An anchor** ([`Anchor`]) is a registered anchor key's signature over
//!   [`anchor_digest`]: one root of a kind per space and window, at a venue.
//! - **Registration** is a founding key's signature over
//!   [`register_digest`], which names the venue, the space and its
//!   controller; the space anchors from the venue's next window.
//! - **A venue's id** ([`VenueId`]) separates its anchors and registrations
//!   from another venue's.
//! - **A venue's rules** ([`venue`]): the registration, the anchor rule,
//!   what is anchored and a root's freshness, written once for every
//!   venue.
//!
//! **Encodings.** Every type encodes as SCALE, by hand ([`codec`]): integers
//! fixed-width little-endian, arrays as their bytes, a sequence a compact
//! count then its items, an enum its byte. A decode is canonical (a compact
//! in its shortest mode, an enum's byte one of its values, a genesis of its
//! one version, nothing left over), so a value has one encoding, and the id
//! of a genesis is the hash of the bytes a venue was given.
//!
//! **Domains.** Each digest absorbs its own domain first, and no domain is a
//! prefix of another, so no preimage of one digest is a preimage of another.
//!
//! The crate is `no_std` and depends on BLAKE2b alone, so a chain's runtime
//! can vendor it with nothing else. No input panics it: outside its tests,
//! an index, a slice, an `unwrap`, an `expect`, a `panic!` or an arithmetic
//! that can overflow is a lint error, each one left allowed in place with
//! the reason it cannot fail.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;

pub mod codec;
#[cfg(feature = "suite")]
pub mod suite;
#[cfg(feature = "vectors")]
pub mod vectors;
pub mod venue;

use alloc::vec::Vec;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub use codec::DecodeError;
use codec::Reader;

/// The space id's domain.
pub const SPACE_ID_DOMAIN: &[u8] = b"vos/space/id";
/// The space root's domain.
pub const SPACE_ROOT_DOMAIN: &[u8] = b"vos/space/v1";
/// The anchor digest's domain.
pub const ANCHOR_DOMAIN: &[u8] = b"vos/anchor/v1";
/// The registration digest's domain.
pub const REGISTER_DOMAIN: &[u8] = b"vos/space/register";
/// A JAM venue's id's domain.
pub const JAM_VENUE_DOMAIN: &[u8] = b"vos/venue/jam";

/// The genesis's version, the one its encoding writes and
/// [`SpaceGenesis::decode`] reads.
pub const GENESIS_VERSION: u8 = 1;

/// The shortest window a venue registers, two minutes.
pub const MIN_LENGTH_MS: u64 = 120_000;
/// The longest window a venue registers, an hour.
pub const MAX_LENGTH_MS: u64 = 3_600_000;
/// The window's length a space takes unless its founder chooses another.
pub const DEFAULT_LENGTH_MS: u64 = 600_000;
/// How long past its window's boundary a venue accepts and keeps an anchor:
/// a day, with no separate grace.
pub const MAX_ROOT_AGE_MS: u64 = 86_400_000;
/// The most founding keys a genesis a venue registers holds; it holds at
/// least one.
pub const MAX_FOUNDING_KEYS: usize = 16;
/// The most the representative's clock lags the space's.
pub const MAX_REPRESENTATIVE_DELAY_MS: u64 = 120_000;

/// BLAKE2b-256 of `parts`, concatenated.
pub fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A node's number in its space.
pub type NodeNumber = u8;

/// The clock that numbers a space's windows, frozen in its genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WindowClock {
    /// Where window 0 starts: milliseconds since the Unix epoch.
    pub origin_ms: u64,
    /// Each window's length in milliseconds.
    pub length_ms: u64,
}

impl Default for WindowClock {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl WindowClock {
    /// The bytes of its encoding.
    pub const BYTES: usize = 16;

    /// The default clock: the Unix epoch as its origin, and the default
    /// length. A node whose space has no genesis names it.
    pub const DEFAULT: Self = Self {
        origin_ms: 0,
        length_ms: DEFAULT_LENGTH_MS,
    };

    /// The window holding time `t` (milliseconds since the Unix epoch):
    /// `⌊(t − origin_ms) / length_ms⌋`; none before the origin, or for a
    /// clock of no length.
    pub fn window(&self, t: u64) -> Option<u64> {
        let since = t.checked_sub(self.origin_ms)?;
        since.checked_div(self.length_ms)
    }

    /// Window `w`'s boundary `B_w = origin_ms + (w+1)·length_ms`, the first
    /// time past it; none past `u64`'s range.
    pub fn boundary(&self, w: u64) -> Option<u64> {
        w.checked_add(1)?
            .checked_mul(self.length_ms)?
            .checked_add(self.origin_ms)
    }

    /// Whether its length is one a venue registers: from [`MIN_LENGTH_MS`]
    /// to [`MAX_LENGTH_MS`].
    pub fn registrable(&self) -> bool {
        (MIN_LENGTH_MS..=MAX_LENGTH_MS).contains(&self.length_ms)
    }

    /// The representative's clock: the space's, its origin later by
    /// `D = min(length_ms / 5, 120,000)`, so the representative's cut of
    /// window w, at `B_w + D`, closes it. None past `u64`'s range.
    pub fn representative(&self) -> Option<Self> {
        let delay = (self.length_ms / 5).min(MAX_REPRESENTATIVE_DELAY_MS);
        Some(Self {
            origin_ms: self.origin_ms.checked_add(delay)?,
            length_ms: self.length_ms,
        })
    }

    /// Its encoding: the origin, then the length.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.origin_ms.to_le_bytes());
        out.extend_from_slice(&self.length_ms.to_le_bytes());
    }

    /// A clock, read from `reader`: any origin and length.
    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            origin_ms: reader.u64()?,
            length_ms: reader.u64()?,
        })
    }
}

/// A space's founding record: its id is its hash ([`space_id`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpaceGenesis {
    /// The founding nodes' numbers and ed25519 keys, by ascending number:
    /// the space's first anchor keys. A venue registers 1 to
    /// [`MAX_FOUNDING_KEYS`].
    pub nodes: Vec<(NodeNumber, [u8; 32])>,
    /// The space's clock: a space with another clock is another space.
    pub clock: WindowClock,
    /// Milliseconds since the Unix epoch, by the founder's clock.
    pub time: u64,
    /// Two spaces of the same nodes, clock and time differ by it.
    pub nonce: [u8; 16],
}

impl SpaceGenesis {
    /// Its canonical encoding: [`GENESIS_VERSION`]; the nodes, a compact
    /// count then each its number (1 byte) and key; the clock; the time;
    /// the nonce.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }

    /// [`SpaceGenesis::encode`], appended to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(GENESIS_VERSION);
        codec::compact(out, self.nodes.len() as u64);
        for (number, key) in &self.nodes {
            out.push(*number);
            out.extend_from_slice(key);
        }
        self.clock.encode_to(out);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.nonce);
    }

    /// The genesis `bytes` encode, all of them, canonically: of version
    /// [`GENESIS_VERSION`], with at least one node, their numbers strictly
    /// ascending, so one set of founders has one encoding. How many a venue
    /// registers is the venue's check ([`MAX_FOUNDING_KEYS`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let genesis = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(genesis)
    }

    /// A genesis of version [`GENESIS_VERSION`], read from `reader`.
    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if reader.u8()? != GENESIS_VERSION {
            return Err(DecodeError::Noncanonical);
        }
        let count = reader.count(1 + 32)?;
        let nodes: Vec<(NodeNumber, [u8; 32])> = (0..count)
            .map(|_| Ok((reader.u8()?, reader.array()?)))
            .collect::<Result<_, DecodeError>>()?;
        if nodes.is_empty() || !nodes.is_sorted_by(|a, b| a.0 < b.0) {
            return Err(DecodeError::Noncanonical);
        }
        Ok(Self {
            nodes,
            clock: WindowClock::decode_from(reader)?,
            time: reader.u64()?,
            nonce: reader.array()?,
        })
    }
}

/// A space's id: `BLAKE2b-256("vos/space/id" ‖ SCALE(genesis))`.
pub fn space_id(genesis: &SpaceGenesis) -> SpaceId {
    SpaceId(blake2b_256(&[SPACE_ID_DOMAIN, &genesis.encode()]))
}

/// A space's id, its genesis's hash ([`space_id`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceId(pub [u8; 32]);

impl SpaceId {
    /// No space: a rootless statement's, and an agent's that no genesis
    /// names.
    pub const NONE: Self = Self([0; 32]);
}

/// A venue's id, which its anchors and registrations sign: Kreivo's is its
/// genesis block's hash; a JAM service's is [`VenueId::jam`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VenueId(pub [u8; 32]);

impl VenueId {
    /// A JAM service's: `BLAKE2b-256("vos/venue/jam" ‖ genesis ‖ service
    /// (4, LE))`, `genesis` the JAM chain's genesis hash.
    pub fn jam(genesis: &[u8; 32], service: u32) -> Self {
        Self(blake2b_256(&[
            JAM_VENUE_DOMAIN,
            genesis,
            &service.to_le_bytes(),
        ]))
    }
}

/// What a root is of, its byte in every encoding. One kind is known; any
/// other byte is refused at decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum RootKind {
    /// A space root `S_w` ([`space_root`]) over its representative's
    /// Blake2b tree.
    Space = 0,
}

impl RootKind {
    /// The kind byte `byte` names; none for an unknown one.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Space),
            _ => None,
        }
    }

    /// A kind, read from `reader`, an unknown byte refused.
    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        reader.u8()?.try_into()
    }
}

impl TryFrom<u8> for RootKind {
    type Error = DecodeError;

    fn try_from(byte: u8) -> Result<Self, DecodeError> {
        Self::from_u8(byte).ok_or(DecodeError::Noncanonical)
    }
}

/// A root a kernel read: of what kind, whose space, as of which window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RootRead {
    pub kind: RootKind,
    pub space: SpaceId,
    pub window: u64,
    pub root: [u8; 32],
}

impl RootRead {
    /// The bytes of its encoding.
    pub const BYTES: usize = 1 + 32 + 8 + 32;

    /// Its encoding: the kind's byte, the space, the window, the root.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend_from_slice(&self.space.0);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.extend_from_slice(&self.root);
    }

    /// A root read, an unknown kind refused.
    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: RootKind::decode_from(reader)?,
            space: SpaceId(reader.array()?),
            window: reader.u64()?,
            root: reader.array()?,
        })
    }
}

/// A space's root of window `window`:
/// `BLAKE2b-256("vos/space/v1" ‖ space ‖ window (8, LE) ‖ rep_root)`,
/// `rep_root` the representative's agent root at its cut of the window.
pub fn space_root(space: &SpaceId, window: u64, rep_root: &[u8; 32]) -> [u8; 32] {
    blake2b_256(&[SPACE_ROOT_DOMAIN, &space.0, &window.to_le_bytes(), rep_root])
}

/// What an anchor key signs to anchor `root` as the space's root of `kind`
/// at `window`, at `venue`:
/// `BLAKE2b-256("vos/anchor/v1" ‖ venue ‖ space ‖ window (8, LE) ‖ kind (1) ‖ root)`.
pub fn anchor_digest(
    venue: &VenueId,
    space: &SpaceId,
    window: u64,
    kind: RootKind,
    root: &[u8; 32],
) -> [u8; 32] {
    blake2b_256(&[
        ANCHOR_DOMAIN,
        &venue.0,
        &space.0,
        &window.to_le_bytes(),
        &[kind as u8],
        root,
    ])
}

/// What a founding key signs to register its space at `venue` under
/// `controller` (a venue account's 32 bytes):
/// `BLAKE2b-256("vos/space/register" ‖ venue ‖ space ‖ controller)`. The
/// space anchors from the venue's next window, which nobody signs, so a
/// replayed registration has no field to change; a venue never forgets a
/// space it registered, so it is refused.
pub fn register_digest(venue: &VenueId, space: &SpaceId, controller: &[u8; 32]) -> [u8; 32] {
    blake2b_256(&[REGISTER_DOMAIN, &venue.0, &space.0, controller])
}

/// A space's root of a kind at a window, signed by one of its anchor keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Anchor {
    pub space: SpaceId,
    pub window: u64,
    pub kind: RootKind,
    pub root: [u8; 32],
    /// The anchor key, ed25519.
    pub signer: [u8; 32],
    /// The signer's signature over [`Anchor::digest`].
    pub signature: [u8; 64],
}

impl Anchor {
    /// The bytes of its encoding.
    pub const BYTES: usize = 32 + 8 + 1 + 32 + 32 + 64;

    /// What its signer signs at `venue` ([`anchor_digest`]).
    pub fn digest(&self, venue: &VenueId) -> [u8; 32] {
        anchor_digest(venue, &self.space, self.window, self.kind, &self.root)
    }

    /// Its encoding: the space, the window, the kind's byte, the root, the
    /// signer, the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.space.0);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.signer);
        out.extend_from_slice(&self.signature);
        out
    }

    /// The anchor `bytes` encode, all of them, an unknown kind refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let anchor = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(anchor)
    }

    /// An anchor, read from `reader`, an unknown kind refused.
    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            space: SpaceId(reader.array()?),
            window: reader.u64()?,
            kind: RootKind::decode_from(reader)?,
            root: reader.array()?,
            signer: reader.array()?,
            signature: reader.array()?,
        })
    }
}

#[cfg(test)]
mod tests;
