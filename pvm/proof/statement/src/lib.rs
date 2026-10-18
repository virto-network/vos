//! A proved statement as a venue judges it (`proving.md` §3.6): the
//! [`Statement`], its canonical encoding, its io-hash and its id, and
//! [`judge`], the venue's check of a final proof against it.
//!
//! **What binds what.** The final proof (`vos-final-verifier`, format 28)
//! states two public inputs, the program id and the io-hash. The io-hash is
//! BLAKE2b-256 of `vos/io/v1` and the statement's `public_args`, `output` and
//! `roots` in their SCALE encoding, as the kernel computes it at its halt
//! (`vos_pvm_precompiles::compute_io_hash`): the proof binds those three
//! fields through it. The venue binds the rest:
//! - **the format,** one it accepts and this verifier reads;
//! - **the program,** against the id the venue pinned;
//! - **the space,** equal to every root's, or [`SpaceId::NONE`] for a
//!   rootless statement;
//! - **the roots,** each anchored for its space and window (`proving.md`
//!   §7);
//! - **repeats,** a statement id it has accepted before refused.
//!
//! **A rootless statement belongs to no space; a statement claiming a space
//! must read a root of it.** The id hashes the space, and only a root binds
//! it: the proof states none, so a rootless statement's space is whatever
//! its submitter writes. Were any space allowed, one accepted proof would
//! make a new id under each, and a venue's repeat check would let it be
//! applied again. [`judge`] refuses a rootless statement whose space is not
//! [`SpaceId::NONE`] ([`Refusal::Space`]).
//!
//! **The program id is the venue's, never the caller's.** [`judge`] takes it
//! as `program`, the id the venue pinned for the kernel whose handler will
//! act on the statement: governance input, set when the kernel was admitted,
//! which anyone with the recursion stack can recompute from the kernel. The
//! statement's own `program` field must equal it. A venue that verified
//! against the statement's or the proof's program id instead would accept
//! any kernel's proof, a statement of the attacker's own program.
//!
//! **Keys.** A venue remembers what it accepted by the statement's id
//! ([`Statement::id`]), never by the proof's bytes or their hash: a proof has
//! many encodings (`vos_final_verifier::decode`), and many proofs state one
//! statement.
//!
//! **The encoding** is SCALE: the format and the program id's eight words as
//! little-endian `u32`s, the space's 32 bytes, then `public_args`, `output`
//! and `roots` as the io-hash encodes them: a byte vector a compact length
//! then its bytes, the roots a compact count then each [`RootRead`] as its
//! kind byte, its space, its window as eight little-endian bytes and its
//! root. A decode is canonical, so a statement has one encoding.
//!
//! The crate is `no_std` and depends on nothing of VOS beyond the final
//! verifier, so a chain's runtime (Kreivo's pallet) can depend on it.

#![no_std]

extern crate alloc;
#[cfg(feature = "fixtures")]
extern crate std;

mod codec;
#[cfg(feature = "fixtures")]
pub mod fixtures;
pub mod model;

use alloc::vec::Vec;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub use codec::DecodeError;
use codec::Reader;
pub use vos_final_verifier;

/// The io-hash's domain (`vos_pvm_precompiles::io::IO_HASH_DOMAIN`).
pub const IO_DOMAIN: &[u8] = b"vos/io/v1";
/// The statement id's domain.
pub const ID_DOMAIN: &[u8] = b"vos/statement/v1";

/// The format of the final proofs [`judge`] reads.
pub const FORMAT: u32 = vos_final_verifier::FORMAT;

/// The bytes of a [`RootRead`]'s encoding.
pub(crate) const ROOT_READ_BYTES: usize = 1 + 32 + 8 + 32;

/// BLAKE2b-256 of `parts`, concatenated.
pub fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

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

/// A space's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceId(pub [u8; 32]);

impl SpaceId {
    /// No space: a rootless statement's, the only one [`judge`] accepts for
    /// it (the crate's docs).
    pub const NONE: Self = Self([0; 32]);
}

/// A root a kernel read: of what kind, whose space, as of which window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RootRead {
    pub kind: u8,
    pub space: SpaceId,
    pub window: u64,
    pub root: [u8; 32],
}

impl RootRead {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.space.0);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.extend_from_slice(&self.root);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: reader.u8()?,
            space: SpaceId(reader.array()?),
            window: reader.u64()?,
            root: reader.array()?,
        })
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
        let count = reader.count(ROOT_READ_BYTES)?;
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

    /// `BLAKE2b-256("vos/statement/v1" ‖ format ‖ program ‖ space ‖
    /// io_hash)`, the format a little-endian `u32` and the program id its
    /// 32 bytes.
    pub fn id(&self) -> StatementId {
        self.id_of(&self.io_hash())
    }

    fn id_of(&self, io_hash: &[u8; 32]) -> StatementId {
        StatementId(blake2b_256(&[
            ID_DOMAIN,
            &self.format.to_le_bytes(),
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

/// What a venue knows: the formats it accepts, its anchored roots and the
/// statements it has accepted.
pub trait Venue {
    /// Whether it accepts final proofs of `format`.
    fn accepts(&self, format: u32) -> bool;
    /// Whether `root` is the anchored root of its space at its window.
    fn anchored(&self, root: &RootRead) -> bool;
    /// Whether it has accepted the statement `id`.
    fn seen(&self, id: &StatementId) -> bool;
}

/// Why a venue refuses a statement.
#[derive(Clone, Debug)]
pub enum Refusal {
    /// The statement does not decode.
    Statement(DecodeError),
    /// A format the venue does not accept, or this verifier does not read.
    Format,
    /// The statement's program is not the one the venue pinned.
    Program,
    /// A root of another space than the statement's, or a rootless
    /// statement claiming a space.
    Space,
    /// A root the venue has not anchored: stale, or unknown.
    Unanchored,
    /// A statement the venue has accepted before.
    Repeated,
    /// The final proof is refused against the venue's program id and the
    /// io-hash recomputed from the statement.
    Proof(vos_final_verifier::Error),
}

impl Refusal {
    /// The refusal's class, as every venue reports it: never 0, which
    /// reports an acceptance. A refused proof is `0x100` and the final
    /// verifier's code (`vos_final_verifier::Error::code`).
    pub fn code(&self) -> u32 {
        match self {
            Self::Statement(_) => 1,
            Self::Format => 2,
            Self::Program => 3,
            Self::Space => 4,
            Self::Unanchored => 5,
            Self::Repeated => 6,
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
                f.write_str("a root is of another space, or a rootless statement claims one")
            }
            Self::Unanchored => f.write_str("a root is not anchored"),
            Self::Repeated => f.write_str("the statement was accepted before"),
            Self::Proof(error) => write!(f, "the proof: {error}"),
        }
    }
}

/// A verdict's code: 0 for an acceptance, a refusal's
/// ([`Refusal::code`]).
pub fn code(verdict: &Result<StatementId, Refusal>) -> u32 {
    verdict.as_ref().map_or_else(Refusal::code, |_| 0)
}

/// A statement the venue's checks before the proof admit: its id, and the
/// public words its proof must state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub id: StatementId,
    pub words: [u32; vos_final_verifier::PUBLIC_WORDS],
}

impl Admitted {
    /// The final proof in `proof`'s bytes, verified against the admitted
    /// words; the statement's id when accepted.
    pub fn verify(&self, proof: &[u8]) -> Result<StatementId, Refusal> {
        vos_final_verifier::verify_bytes(proof, &self.words).map_err(Refusal::Proof)?;
        Ok(self.id)
    }
}

/// The venue's checks of `statement` before its proof: the words its proof
/// must state, and its id.
///
/// `program` is the id the venue pinned for the kernel whose handler acts
/// on the statement, never one the caller supplies (the crate's docs).
///
/// In order: the format; the statement's program against `program`; the
/// space, every root's equal to the statement's and a rootless statement's
/// [`SpaceId::NONE`]; every root anchored; the io-hash recomputed from the
/// fields and the id from it; a repeat.
pub fn admit(
    venue: &impl Venue,
    program: &ProgramId,
    statement: &Statement,
) -> Result<Admitted, Refusal> {
    if statement.format != FORMAT || !venue.accepts(statement.format) {
        return Err(Refusal::Format);
    }
    if statement.program != *program {
        return Err(Refusal::Program);
    }
    let spaced = if statement.roots.is_empty() {
        statement.space == SpaceId::NONE
    } else {
        statement
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
    let words = vos_final_verifier::Statement {
        program: program.0,
        io_hash,
    }
    .words();
    Ok(Admitted { id, words })
}

/// The venue's check of `proof`, a final proof's bytes, against `statement`;
/// its id, when accepted. The venue records the id after it.
///
/// `program` is the id the venue pinned for the kernel whose handler acts
/// on the statement, never one the caller supplies (the crate's docs).
///
/// [`admit`]'s checks, then the proof, verified against `program` and the
/// recomputed io-hash.
pub fn judge(
    venue: &impl Venue,
    program: &ProgramId,
    statement: &Statement,
    proof: &[u8],
) -> Result<StatementId, Refusal> {
    admit(venue, program, statement)?.verify(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) fn statement() -> Statement {
        let space = SpaceId([0xa1; 32]);
        Statement {
            format: FORMAT,
            program: ProgramId(core::array::from_fn(|i| 1_000 + i as u32)),
            space,
            public_args: vec![7, 7, 7],
            output: (0..100).collect(),
            roots: vec![
                RootRead {
                    kind: 1,
                    space,
                    window: 41,
                    root: [0x41; 32],
                },
                RootRead {
                    kind: 1,
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
    /// tail; the id over the format, the program, the space and the
    /// io-hash; and both pinned.
    #[test]
    fn the_encoding_the_io_hash_and_the_id() {
        let statement = statement();
        let bytes = statement.encode();
        assert_eq!(bytes.len(), 4 + 32 + 32 + 1 + 3 + 2 + 100 + 1 + 2 * 73);
        assert_eq!(&bytes[..4], &28u32.to_le_bytes());
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
                kind: root.kind,
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
            blake2b_256(&[b"vos/statement/v1", &bytes[..68], &io_hash])
        );
        assert_eq!(
            hex(&io_hash),
            "46a7161512387eab75ff585a8252b365ef60ab11489db391ba184665b0118bdf"
        );
        assert_eq!(
            hex(&statement.id().0),
            "143db435d3cdd4901aca106e1de777924cfd5dd7ef930b3cc6e1f637c40dfb2a"
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

    /// Each field moves the io-hash or the id: the format, the program and
    /// the space only the id, the rest both.
    #[test]
    fn every_field_is_bound() {
        let base = statement();
        type Change = fn(&mut Statement);
        let changes: [(&str, bool, Change); 9] = [
            ("format", false, |s| s.format = 30),
            ("program", false, |s| s.program.0[7] += 1),
            ("space", false, |s| s.space.0[0] ^= 1),
            ("public_args", true, |s| s.public_args.push(0)),
            ("output", true, |s| s.output[99] ^= 1),
            ("a root's kind", true, |s| s.roots[0].kind = 2),
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
}
