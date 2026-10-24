//! A proved statement as a venue judges it (`proving.md` §3.6): the
//! [`Statement`], its canonical encoding, its io-hash and its id, and
//! [`judge`], the venue's check of a final proof against it.
//!
//! **What binds what.** The final proof (`vos-pvm-final-verifier`, `format::MASKED_WRAP`;
//! 28 under `test-formats`) states two public inputs, the program id and the
//! io-hash. The io-hash is BLAKE2b-256 of `vos/io/v1` and the statement's
//! `public_args`, `output` and `roots` in their SCALE encoding, as the
//! kernel computes it at its halt (`vos_pvm_precompiles::compute_io_hash`):
//! the proof binds those three fields through it. The venue binds the rest:
//! - **the format,** one it accepts and this build links ([`LINKED`]);
//! - **the program,** against the id the venue pinned ([`Pin`]);
//! - **the venue,** for a venue-bound program: the first 32 bytes of
//!   `public_args` the venue's id ([`Refusal::Venue`]);
//! - **the space,** equal to every root's, or [`SpaceId::NONE`] for a
//!   rootless statement;
//! - **the roots,** each anchored for its space and window, within the
//!   space's range at the venue (`proving.md` §7);
//! - **repeats,** a statement id it has accepted before refused, under the
//!   `Seen` rule ([`seen_expiry`]).
//!
//! **A rootless statement belongs to no space; a statement claiming a space
//! must read a root of it.** The id hashes the space, and only a root binds
//! it: the proof states none, so a rootless statement's space is whatever
//! its submitter writes. Were any space allowed, one accepted proof would
//! make a new id under each, and a venue's repeat check would let it be
//! applied again. [`judge`] refuses a rootless statement whose space is not
//! [`SpaceId::NONE`], and a rooted one whose space is ([`Refusal::Space`]):
//! no space has the id `NONE`, and an agent of no space states no root, so
//! a root of `NONE` is never one a venue anchored, and is refused as a
//! claim before any anchor is looked up.
//!
//! **The program id is the venue's, never the caller's.** [`judge`] takes it
//! in a [`Pin`], the id the venue pinned for the kernel whose handler will
//! act on the statement: governance input, set when the kernel was admitted,
//! which anyone with the recursion stack can recompute from the kernel. The
//! statement's own `program` field must equal it. A venue that verified
//! against the statement's or the proof's program id instead would accept
//! any kernel's proof, a statement of the attacker's own program.
//!
//! **A venue-bound program's statements are one venue's.** The pin says
//! whether the program is venue-bound (`#[attestable(venue_bound)]`): its
//! kernel takes the venue's id as its first public argument, so
//! `public_args[..32]` is the venue the statement was made for, bound by
//! the io-hash. A venue refuses one naming another ([`Refusal::Venue`]), so
//! a statement accepted at one venue is not accepted, and handled, at
//! another. A program that is not venue-bound states nothing of the venue;
//! its statements are accepted at every venue that pins it.
//!
//! **Formats.** [`judge`] reads a statement's proof under the statement's
//! format, through the final verifier's dispatch, when the venue accepts it
//! and this build links it ([`LINKED`]): `format::MASKED_WRAP` alone, and 28 beside it
//! only under the `test-formats` feature, which no production build
//! enables (`just check-no-test-formats`). So the accepted set is the one
//! gate between `format::WRAP` and a production venue.
//!
//! **Keys.** A venue remembers what it accepted by the statement's id
//! ([`Statement::id`]), never by the proof's bytes or their hash: a proof has
//! many encodings under `format::WRAP` (`vos_pvm_final_verifier::unmasked::decode`),
//! and many proofs state one statement.
//!
//! **`Seen` and time** ([`seen_expiry`]): a rooted statement's entry may be
//! dropped once its newest root is past [`MAX_ROOT_AGE_MS`], since a replay
//! then fails as unanchored. A rootless statement's entry never expires: it
//! has no anchor to fail, so a dropped entry would let it be accepted, and
//! handled, again.
//!
//! **The id does not hash the format.** The format is a checked field, as
//! the space is, but which final proof states a run is not part of what it
//! states: a venue accepts two final formats during a transition, and one
//! run wrapped under each is one statement, refused the second time. The
//! program id does not move with the final format (it covers the segment
//! format only), so an id that hashed the format would give one run an id
//! per format, and a venue's repeat check would let it be applied once
//! under each.
//!
//! **The encoding** is SCALE: the format and the program id's eight words as
//! little-endian `u32`s, the space's 32 bytes, then `public_args`, `output`
//! and `roots` as the io-hash encodes them: a byte vector a compact length
//! then its bytes, the roots a compact count then each [`RootRead`] as its
//! kind byte, its space, its window as eight little-endian bytes and its
//! root. A decode is canonical, an unknown root kind refused, so a statement
//! has one encoding.
//!
//! The crate is `no_std` and depends on nothing of VOS beyond the final
//! verifier and `vos-anchor` (the space's types, re-exported), so a chain's
//! runtime (Kreivo's pallet) can depend on it. No input panics it: outside
//! its tests and the harnesses' fixtures reader, an index, a slice, an
//! `unwrap`, an `expect`, a `panic!` or an arithmetic that can overflow is
//! a lint error, each one left allowed in place with the reason it cannot
//! fail.

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
#[cfg(feature = "fixtures")]
extern crate std;

#[cfg(feature = "fixtures")]
pub mod fixtures;
pub mod model;

use alloc::vec::Vec;

use vos_anchor::codec::{self, Reader};
pub use vos_anchor::{
    self, DecodeError, MAX_ROOT_AGE_MS, RootKind, RootRead, SpaceId, VenueId, WindowClock,
    blake2b_256,
};
pub use vos_pvm_final_verifier;

/// The io-hash's domain (`vos_pvm_precompiles::io::IO_HASH_DOMAIN`).
pub const IO_DOMAIN: &[u8] = b"vos/io/v1";
/// The statement id's domain.
pub const ID_DOMAIN: &[u8] = b"vos/statement/v1";

/// The final formats this build reads: 39, and 28 under the `test-formats`
/// feature (`vos_pvm_final_verifier::LINKED`). A venue refuses a statement
/// of any other as [`Refusal::Format`], whatever it accepts.
pub const LINKED: &[u32] = vos_pvm_final_verifier::LINKED;

/// A kernel's program id: eight M31 words, each below `p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProgramId(pub [u32; 8]);

impl ProgramId {
    /// The 32-byte form: each word as four little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(&self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

/// A statement's id, what a venue remembers it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatementId(pub [u8; 32]);

/// What a final proof proves, as a venue receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The final proof's format; the venue checks it accepts it.
    pub format: u32,
    /// The kernel's program id, a public input of the proof.
    pub program: ProgramId,
    /// The space every root is of, which the venue checks; [`SpaceId::NONE`]
    /// when there are no roots.
    pub space: SpaceId,
    /// The kernel's `#[public]` arguments, in their canonical encoding.
    pub public_args: Vec<u8>,
    /// The kernel's output, opaque; the program's handler decodes it.
    pub output: Vec<u8>,
    /// The roots the kernel read, in its order.
    pub roots: Vec<RootRead>,
}

impl Statement {
    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }

    pub(crate) fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.program.to_bytes());
        out.extend_from_slice(&self.space.0);
        self.encode_io_to(out);
    }

    /// `public_args`, `output` and `roots`, as the io-hash encodes them.
    fn encode_io_to(&self, out: &mut Vec<u8>) {
        for bytes in [&self.public_args, &self.output] {
            codec::compact(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        codec::compact(out, self.roots.len() as u64);
        for root in &self.roots {
            root.encode_to(out);
        }
    }

    /// The statement `bytes` encode, all of them, canonically.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let statement = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(statement)
    }

    pub(crate) fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let format = reader.u32()?;
        let program = decode_program(reader)?;
        let space = SpaceId(reader.array()?);
        let public_args = reader.bytes()?;
        let output = reader.bytes()?;
        let count = reader.count(RootRead::BYTES)?;
        let roots = (0..count)
            .map(|_| RootRead::decode_from(reader))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            format,
            program,
            space,
            public_args,
            output,
            roots,
        })
    }

    /// `BLAKE2b-256("vos/io/v1" ‖ public_args ‖ output ‖ roots)`, each in
    /// its SCALE encoding: what the kernel computed at its halt, and the
    /// proof states.
    pub fn io_hash(&self) -> [u8; 32] {
        let mut io = Vec::new();
        self.encode_io_to(&mut io);
        blake2b_256(&[IO_DOMAIN, &io])
    }

    /// `BLAKE2b-256("vos/statement/v1" ‖ program ‖ space ‖ io_hash)`, the
    /// program id its 32 bytes: not the format, which a venue checks but
    /// which does not change what is stated (the crate's docs).
    pub fn id(&self) -> StatementId {
        self.id_of(&self.io_hash())
    }

    fn id_of(&self, io_hash: &[u8; 32]) -> StatementId {
        StatementId(blake2b_256(&[
            ID_DOMAIN,
            &self.program.to_bytes(),
            &self.space.0,
            io_hash,
        ]))
    }
}

/// A program id's eight words, each below `p`.
pub(crate) fn decode_program(reader: &mut Reader<'_>) -> Result<ProgramId, DecodeError> {
    let mut words = [0u32; 8];
    for word in &mut words {
        *word = reader.u32()?;
        if *word >= P {
            return Err(DecodeError::Noncanonical);
        }
    }
    Ok(ProgramId(words))
}

/// The M31 modulus.
const P: u32 = (1 << 31) - 1;

/// What a venue pinned for a kernel whose handler acts on its statements:
/// the program id, and whether the program is venue-bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pin {
    /// The kernel's program id, the one its proofs are verified against.
    pub program: ProgramId,
    /// Whether the program is venue-bound (`#[attestable(venue_bound)]`): its
    /// statements' `public_args` start with the venue's id.
    pub venue_bound: bool,
}

/// What a venue knows: its id, the formats it accepts, its anchored roots
/// and the statements it has accepted.
pub trait Venue {
    /// Its id: on Kreivo its genesis hash; on JAM `VenueId::jam`'s.
    fn id(&self) -> VenueId;
    /// Whether it accepts final proofs of `format`.
    fn accepts(&self, format: u32) -> bool;
    /// Whether `root` is the anchored root of its space at its window: the
    /// window within the space's range at this venue (from its registration
    /// to its migration away, if any) and the root not past
    /// [`MAX_ROOT_AGE_MS`] by the venue's time.
    fn anchored(&self, root: &RootRead) -> bool;
    /// Whether it holds a `Seen` entry for the statement `id`
    /// ([`seen_expiry`]).
    fn seen(&self, id: &StatementId) -> bool;
}

/// When a venue may drop the `Seen` entry of `statement`, accepted: the
/// venue's time in milliseconds past which a replay fails without it, or
/// `u64::MAX` for never.
///
/// A rooted statement's entry lasts until its newest root is past
/// [`MAX_ROOT_AGE_MS`] (`B_w + MaxRootAge`, `clock` its space's): a replay
/// after it is refused as [`Refusal::Unanchored`], since no venue anchors a
/// root past that age. A rootless statement's never expires: it has no
/// anchor to fail, so a dropped entry would let it be accepted, and
/// handled, again; their count is bounded by what a submit costs. A
/// boundary past `u64`'s range keeps the entry for ever too.
pub fn seen_expiry(statement: &Statement, clock: &WindowClock) -> u64 {
    statement
        .roots
        .iter()
        .map(|root| root.window)
        .max()
        .and_then(|window| clock.boundary(window))
        .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
        .unwrap_or(u64::MAX)
}

/// Why a venue refuses a statement.
#[derive(Clone, Debug)]
pub enum Refusal {
    /// The statement does not decode.
    Statement(DecodeError),
    /// A format the venue does not accept, or this build does not link.
    Format,
    /// The statement's program is not the one the venue pinned.
    Program,
    /// A root of another space than the statement's, a rootless statement
    /// claiming a space, or a rooted one claiming none.
    Space,
    /// A root the venue has not anchored: stale, outside the space's range
    /// at the venue, or unknown.
    Unanchored,
    /// A statement the venue has accepted before.
    Repeated,
    /// A venue-bound program's statement whose `public_args` do not start
    /// with this venue's id.
    Venue,
    /// The final proof is refused against the venue's program id and the
    /// io-hash recomputed from the statement.
    Proof(vos_pvm_final_verifier::Error),
}

impl Refusal {
    /// The refusal's class, as every venue reports it: never 0, which
    /// reports an acceptance. A refused proof is `0x100` and the final
    /// verifier's code (`vos_pvm_final_verifier::Error::code`).
    pub fn code(&self) -> u32 {
        match self {
            Self::Statement(_) => 1,
            Self::Format => 2,
            Self::Program => 3,
            Self::Space => 4,
            Self::Unanchored => 5,
            Self::Repeated => 6,
            Self::Venue => 7,
            Self::Proof(error) => 0x100 | u32::from(error.code()),
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Statement(error) => write!(f, "the statement: {error}"),
            Self::Format => f.write_str("the format is not accepted"),
            Self::Program => f.write_str("the statement's program is not the pinned one"),
            Self::Space => {
                f.write_str(
                "a root is of another space, a rootless statement claims one, or a rooted one claims none",
            )
            }
            Self::Unanchored => f.write_str("a root is not anchored"),
            Self::Repeated => f.write_str("the statement was accepted before"),
            Self::Venue => f.write_str("the statement is bound to another venue"),
            Self::Proof(error) => write!(f, "the proof: {error}"),
        }
    }
}

/// A verdict's code: 0 for an acceptance, a refusal's
/// ([`Refusal::code`]).
pub fn code(verdict: &Result<StatementId, Refusal>) -> u32 {
    verdict.as_ref().map_or_else(Refusal::code, |_| 0)
}

/// A statement the venue's checks before the proof admit: its format, its
/// id, and the public words its proof must state. Only [`admit`] makes one,
/// so a proof is verified against a statement its checks passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    format: u32,
    id: StatementId,
    words: [u32; vos_pvm_final_verifier::PUBLIC_WORDS],
}

impl Admitted {
    /// The statement's format: one the venue accepts and this build links.
    pub fn format(&self) -> u32 {
        self.format
    }

    /// The statement's id.
    pub fn id(&self) -> StatementId {
        self.id
    }

    /// The final proof in `proof`'s bytes, verified under the admitted
    /// format against the admitted words; the statement's id when accepted.
    pub fn verify(&self, proof: &[u8]) -> Result<StatementId, Refusal> {
        vos_pvm_final_verifier::verify(self.format, &[self.format], proof, &self.words)
            .map_err(Refusal::Proof)?;
        Ok(self.id)
    }
}

/// The venue's checks of `statement` before its proof: the words its proof
/// must state, and its id.
///
/// `pin` is what the venue pinned for the kernel whose handler acts on the
/// statement, never what the caller supplies (the crate's docs).
///
/// In order (pin F): the format, accepted by the venue and linked in this
/// build; the statement's program against the pin's; the venue, the first
/// 32 bytes of `public_args` its id, if the program is venue-bound; the
/// space, a rootless statement's [`SpaceId::NONE`] and a rooted statement's
/// not, every root's equal to it; every root anchored; the io-hash
/// recomputed from the fields and the id from it; a repeat. Each before the
/// proof, which is the costly check: a venue that verified first would
/// spend a verify on every replay.
pub fn admit(venue: &impl Venue, pin: &Pin, statement: &Statement) -> Result<Admitted, Refusal> {
    if !LINKED.contains(&statement.format) || !venue.accepts(statement.format) {
        return Err(Refusal::Format);
    }
    if statement.program != pin.program {
        return Err(Refusal::Program);
    }
    if pin.venue_bound && !statement.public_args.starts_with(&venue.id().0) {
        return Err(Refusal::Venue);
    }
    let spaced = if statement.roots.is_empty() {
        statement.space == SpaceId::NONE
    } else {
        statement.space != SpaceId::NONE
            && statement
                .roots
                .iter()
                .all(|root| root.space == statement.space)
    };
    if !spaced {
        return Err(Refusal::Space);
    }
    if !statement.roots.iter().all(|root| venue.anchored(root)) {
        return Err(Refusal::Unanchored);
    }
    let io_hash = statement.io_hash();
    let id = statement.id_of(&io_hash);
    if venue.seen(&id) {
        return Err(Refusal::Repeated);
    }
    let words = vos_pvm_final_verifier::Statement {
        program: pin.program.0,
        io_hash,
    }
    .words();
    Ok(Admitted {
        format: statement.format,
        id,
        words,
    })
}

/// The venue's check of `proof`, a final proof's bytes, against `statement`;
/// its id, when accepted. The venue records the id after it, under the
/// `Seen` rule ([`seen_expiry`]).
///
/// `pin` is what the venue pinned for the kernel whose handler acts on the
/// statement, never what the caller supplies (the crate's docs).
///
/// [`admit`]'s checks, then the proof (at most 256 KiB, the format's own
/// decode, nothing after it), verified against the pinned program id and
/// the recomputed io-hash.
pub fn judge(
    venue: &impl Venue,
    pin: &Pin,
    statement: &Statement,
    proof: &[u8],
) -> Result<StatementId, Refusal> {
    admit(venue, pin, statement)?.verify(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) fn statement() -> Statement {
        let space = SpaceId([0xa1; 32]);
        Statement {
            format: vos_pvm_final_verifier::masked::FORMAT,
            program: ProgramId(core::array::from_fn(|i| 1_000 + i as u32)),
            space,
            public_args: vec![7, 7, 7],
            output: (0..100).collect(),
            roots: vec![
                RootRead {
                    kind: RootKind::Space,
                    space,
                    window: 41,
                    root: [0x41; 32],
                },
                RootRead {
                    kind: RootKind::Space,
                    space,
                    window: 42,
                    root: [0x42; 32],
                },
            ],
        }
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect()
    }

    /// The encoding, field by field, and its decode; the io-hash over its
    /// tail; the id over the program, the space and the io-hash; and both
    /// pinned.
    #[test]
    fn the_encoding_the_io_hash_and_the_id() {
        let statement = statement();
        let bytes = statement.encode();
        assert_eq!(bytes.len(), 4 + 32 + 32 + 1 + 3 + 2 + 100 + 1 + 2 * 73);
        assert_eq!(&bytes[..4], &39u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &1_000u32.to_le_bytes());
        assert_eq!(&bytes[68..72], &[3 << 2, 7, 7, 7]);
        assert_eq!(&bytes[72..74], &[0x91, 0x01]);
        assert_eq!(Statement::decode(&bytes), Ok(statement.clone()));

        let tail = &bytes[68..];
        assert_eq!(statement.io_hash(), blake2b_256(&[b"vos/io/v1", tail]));
        let roots: Vec<vos_pvm_precompiles::RootRead> = statement
            .roots
            .iter()
            .map(|root| vos_pvm_precompiles::RootRead {
                kind: vos_pvm_precompiles::RootKind::try_from(root.kind as u8).unwrap(),
                space: root.space.0,
                window: root.window,
                root: root.root,
            })
            .collect();
        assert_eq!(
            statement.io_hash(),
            vos_pvm_precompiles::compute_io_hash(&statement.public_args, &statement.output, &roots)
        );
        let io_hash = statement.io_hash();
        assert_eq!(
            statement.id().0,
            blake2b_256(&[b"vos/statement/v1", &bytes[4..68], &io_hash])
        );
        assert_eq!(
            hex(&io_hash),
            "e5aed594c742205ea5778f886a3646c2c67b0ec4397743d5dfb363e95c23a32d"
        );
        assert_eq!(
            hex(&statement.id().0),
            "2a98ff7d11931d67f5b8d3b46b173c0b045a6ea7c08791931093a0fe2f01c0ab"
        );
    }

    /// A decode refuses what is not one canonical statement: a byte short,
    /// a byte more, a program word at or above `p`, a length in a longer
    /// compact mode than its own.
    #[test]
    fn a_decode_is_canonical() {
        let bytes = statement().encode();
        assert_eq!(
            Statement::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Short)
        );
        let mut more = bytes.clone();
        more.push(0);
        assert_eq!(Statement::decode(&more), Err(DecodeError::Trailing));
        let mut wide = bytes.clone();
        wide[4..8].copy_from_slice(&P.to_le_bytes());
        assert_eq!(Statement::decode(&wide), Err(DecodeError::Noncanonical));
        // `public_args`' length, 3, in the two-byte mode.
        let long = [&bytes[..68], &[(3 << 2) | 1, 0], &bytes[69..]].concat();
        assert_eq!(Statement::decode(&long), Err(DecodeError::Noncanonical));
    }

    /// A root of an unknown kind is refused at decode: the statement, and a
    /// venue's judgement of it, before any other check.
    #[test]
    fn an_unknown_root_kind_is_refused_at_decode() {
        let bytes = statement().encode();
        // The second root's kind byte: after the roots' count and the first.
        let at = bytes.len() - RootRead::BYTES;
        assert_eq!(bytes[at], RootKind::Space as u8);
        for kind in [1, 2, 0xff] {
            let mut unknown = bytes.clone();
            unknown[at] = kind;
            assert_eq!(Statement::decode(&unknown), Err(DecodeError::Noncanonical));
        }
    }

    /// The kernel's root kinds are the statement's, byte for byte: each
    /// byte names the same kind, or none, in both.
    #[test]
    fn the_kernels_root_kinds_are_the_statements() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                RootKind::from_u8(byte).map(|kind| kind as u8),
                vos_pvm_precompiles::RootKind::from_u8(byte).map(|kind| kind as u8),
                "{byte}"
            );
        }
    }

    /// Each field but the format moves the io-hash or the id: the program
    /// and the space only the id, the rest both. The format moves neither:
    /// one run under two final formats is one statement.
    #[test]
    fn every_field_is_bound() {
        let base = statement();
        let mut reformatted = base.clone();
        reformatted.format = 28;
        assert_eq!(reformatted.io_hash(), base.io_hash());
        assert_eq!(reformatted.id(), base.id());

        type Change = fn(&mut Statement);
        let changes: [(&str, bool, Change); 7] = [
            ("program", false, |s| s.program.0[7] += 1),
            ("space", false, |s| s.space.0[0] ^= 1),
            ("public_args", true, |s| s.public_args.push(0)),
            ("output", true, |s| s.output[99] ^= 1),
            ("a root's window", true, |s| s.roots[1].window += 1),
            ("a root", true, |s| s.roots[1].root[31] ^= 1),
            ("the roots' order", true, |s| s.roots.swap(0, 1)),
        ];
        for (name, io, change) in changes {
            let mut changed = base.clone();
            change(&mut changed);
            assert_eq!(changed.io_hash() != base.io_hash(), io, "{name}");
            assert_ne!(changed.id(), base.id(), "{name}");
        }
        // Bytes moved between `public_args` and `output` move the io-hash.
        let mut moved = base.clone();
        moved.public_args.push(moved.output.remove(0));
        assert_ne!(moved.io_hash(), base.io_hash());
    }

    /// The `Seen` rule: a rooted statement's entry lasts until its newest
    /// root is past `MaxRootAge`, whichever order its roots are in; a
    /// rootless statement's, and one whose boundary overflows, for ever.
    #[test]
    fn a_seen_entry_expires_with_its_newest_root_and_a_rootless_one_never() {
        let clock = WindowClock {
            origin_ms: 1_000,
            length_ms: 600_000,
        };
        let mut rooted = statement();
        let newest = 1_000 + 43 * 600_000 + MAX_ROOT_AGE_MS;
        assert_eq!(seen_expiry(&rooted, &clock), newest);
        rooted.roots.swap(0, 1);
        assert_eq!(seen_expiry(&rooted, &clock), newest);
        rooted.roots[0].window = u64::MAX;
        assert_eq!(seen_expiry(&rooted, &clock), u64::MAX);
        let rootless = Statement {
            space: SpaceId::NONE,
            roots: Vec::new(),
            ..statement()
        };
        assert_eq!(seen_expiry(&rootless, &clock), u64::MAX);
    }
}
