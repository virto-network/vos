//! The final wrap's verifier (`recursion-air.md` §8, `proving.md` §3.5–3.6
//! and §5).
//!
//! A wrap proof states the recursion AIR's three components at the wrap
//! circuit's log sizes ([`LOG_SIZES`]), proved on the Blake2b-256 channel
//! and Merkle trees. Its 24 public words, the program id (8) and the
//! io-hash's 16 limbs, sit at the circuit's addresses 0–23, one word a wire,
//! with zero, one and `u` after them ([`LAYOUT`]). The claimed sums, `u`'s
//! public use and each public word's add to zero: that is what binds the
//! words to the circuit's wires (`vos_pvm_recair_air::gate`).
//!
//! **One format** (`vos_pvm_recair_air::format`): **39** ([`masked`]), the
//! masked wrap, verified by the masked verifier ([`masking`]). Its bytes are a fixed layout ([`masked::decode`]): one
//! encoding a proof.
//!
//! **Dispatch is by the statement's format** ([`verify`], [`decode`]): a
//! venue passes the format its statement names and the set it accepts; a
//! format outside the set, or one this build does not link ([`LINKED`]), is
//! refused, and that format's decode checks the proof's own header against
//! it. The format is never read from the proof's bytes.
//!
//! **Every proof's shape is checked before any Stwo call**: Stwo's verifier
//! refuses a malformed FRI proof, Merkle witness or queried-value shape with
//! an error, but it indexes the sampled values by the components' masks,
//! zips the trees' decommitments and queried values with its own trees, and
//! takes the composition tree as the last commitment: each a panic on a
//! proof whose shape is other than the AIR's.
//!
//! A venue keys what it has accepted on the statement's id (`vos-statement`),
//! never on the proof.
//!
//! The crate is `no_std`, uses no nightly feature, and builds on stable for
//! x86 and wasm32 and on the pinned nightly for the PVM.
//!
//! **No input panics it:** outside its tests, an index, a slice, an
//! `unwrap`, an `expect`, a `panic!` or an arithmetic that can overflow is a
//! lint error, each one left allowed in place with the reason it cannot
//! fail. Stwo's own sites on the verify path, and the shape checks that
//! guard them, are listed in `pvm/proof/SECURITY.md`.

#![no_std]
#![forbid(unsafe_code)]
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

mod constants;
mod layout;
pub mod masked;
pub mod masking;

use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleHasher;
use stwo::core::verifier::VerificationError;
use vos_pvm_recair_air::LogSizes;
use vos_pvm_recair_air::gate::Layout;

pub use constants::{LOG_SIZES, MAX_PROOF_BYTES, PREPROCESSED_ROOT_39, TREE_WIDTHS};
pub use vos_pvm_recair_air;

/// The wrap's public words: the program id's 8, then the io-hash's 16 limbs.
pub const PUBLIC_WORDS: usize = 24;

/// The wrap circuit's reserved wires: its public words at 0–23, then zero,
/// one and `u`.
pub const LAYOUT: Layout = Layout::wrap(PUBLIC_WORDS as u32);

/// The formats this build verifies.
pub const LINKED: &[u32] = &[masked::FORMAT];

/// A wrap proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapProof {
    pub format_version: u32,
    /// `p2`, `qm31`, `h8`.
    pub log_sizes: LogSizes,
    pub interaction_pow: u64,
    pub claimed_sums: [SecureField; 3],
    pub stark_proof: StarkProof<Blake2bMerkleHasher>,
}

/// A kernel's program id (`proving.md` §3.6): eight M31 words, each below
/// `p`. The one type of the value: the prover computes it
/// (`vos_pvm_proof::program_id`), the wrap's public words carry it
/// ([`PublicWords`]), a statement names it and a venue pins it
/// (`vos-statement`, which re-exports it).
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

    /// Its words as field elements, the form a fold recomputes it in.
    pub fn felts(&self) -> [BaseField; 8] {
        self.0.map(BaseField::from_u32_unchecked)
    }
}

impl From<[BaseField; 8]> for ProgramId {
    /// The id of eight field words, each canonical.
    fn from(felts: [BaseField; 8]) -> Self {
        Self(felts.map(|felt| felt.0))
    }
}

/// What a wrap proof's public words state: the program id and the io-hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicWords {
    pub program: ProgramId,
    pub io_hash: [u8; 32],
}

impl PublicWords {
    /// Its 24 public words: the program id, then the io-hash's bytes in
    /// pairs, `b0 + 256·b1`.
    pub fn words(&self) -> [u32; PUBLIC_WORDS] {
        let (pairs, _) = self.io_hash.as_chunks::<2>();
        let limbs = pairs
            .iter()
            .map(|&pair| u32::from(u16::from_le_bytes(pair)));
        let mut words = [0; PUBLIC_WORDS];
        for (word, value) in words
            .iter_mut()
            .zip(self.program.0.into_iter().chain(limbs))
        {
            *word = value;
        }
        words
    }

    /// The public words `words` decoded: each program word below `p`,
    /// each io-hash limb below 2^16.
    pub fn from_words(words: &[u32; PUBLIC_WORDS]) -> Result<Self, Error> {
        let (program, limbs) = words.split_first_chunk::<8>().ok_or(Error::PublicWords)?;
        if program.iter().any(|&word| word >= P) {
            return Err(Error::PublicWords);
        }
        let mut io_hash = [0; 32];
        let (pairs, _) = io_hash.as_chunks_mut::<2>();
        for (pair, &limb) in pairs.iter_mut().zip(limbs) {
            *pair = u16::try_from(limb)
                .map_err(|_| Error::PublicWords)?
                .to_le_bytes();
        }
        Ok(Self {
            program: ProgramId(*program),
            io_hash,
        })
    }
}

/// Why a wrap proof is refused.
#[derive(Clone, Debug)]
pub enum Error {
    /// The bytes do not decode as exactly one proof of the format.
    Decode,
    /// The bytes are longer than [`MAX_PROOF_BYTES`].
    Length,
    /// A public word out of its range.
    PublicWords,
    /// A format outside the accepted set or this build, or a proof of
    /// another format, configuration or log sizes.
    Format,
    /// Another circuit: the preprocessed root is not the wrap's.
    Circuit,
    /// The proof's shape is not the format's.
    Shape(&'static str),
    /// An M31 limb at or above `p`.
    Noncanonical,
    /// The interaction PoW nonce falls short.
    InteractionPow,
    /// The claimed sums and the public terms do not add to zero.
    Logup,
    /// Stwo's verifier refused.
    Stark(VerificationError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode => f.write_str("the bytes are not a wrap proof of the format"),
            Self::Length => f.write_str("the bytes are longer than a wrap proof"),
            Self::PublicWords => f.write_str("a public word is out of its range"),
            Self::Format => f.write_str(
                "the format is not accepted, or the proof is not of it at the wrap's log sizes",
            ),
            Self::Circuit => f.write_str("the proof is of another circuit"),
            Self::Shape(what) => write!(f, "the proof's shape: {what}"),
            Self::Noncanonical => f.write_str("the proof has a noncanonical M31 limb"),
            Self::InteractionPow => f.write_str("the interaction PoW nonce falls short"),
            Self::Logup => f.write_str("the claimed sums and the public terms do not add to zero"),
            Self::Stark(error) => write!(f, "Stwo verification: {error}"),
        }
    }
}

impl Error {
    /// The refusal's class, a byte every venue reports alike: its variant,
    /// and a Stwo refusal's kind (`0x10` and up).
    pub fn code(&self) -> u8 {
        match self {
            Self::Decode => 1,
            Self::Length => 2,
            Self::PublicWords => 3,
            Self::Format => 4,
            Self::Circuit => 5,
            Self::Shape(_) => 6,
            Self::Noncanonical => 7,
            Self::InteractionPow => 8,
            Self::Logup => 9,
            Self::Stark(error) => {
                0x10 | match error {
                    VerificationError::InvalidStructure(_) => 1,
                    VerificationError::Merkle(_) => 2,
                    VerificationError::OodsNotMatching => 3,
                    VerificationError::Fri(_) => 4,
                    VerificationError::ProofOfWork => 5,
                    VerificationError::InvalidLiftingLogSize(_) => 6,
                    VerificationError::InvalidCanonicCosetLogSize(_) => 7,
                }
            }
        }
    }
}

/// A wrap proof decoded under the format a statement names.
#[derive(Clone, Debug)]
pub struct Decoded {
    format: u32,
    proof: WrapProof,
}

impl Decoded {
    /// The format it was decoded under.
    pub fn format(&self) -> u32 {
        self.format
    }

    pub fn proof(&self) -> &WrapProof {
        &self.proof
    }

    pub fn into_proof(self) -> WrapProof {
        self.proof
    }

    /// Verifies the proof under its format against the public `words`, and
    /// returns what they state.
    pub fn verify(self, words: &[u32; PUBLIC_WORDS]) -> Result<PublicWords, Error> {
        match self.format {
            masked::FORMAT => masked::verify(self.proof, words),
            _ => Err(Error::Format),
        }
    }
}

/// The proof in `bytes` under `format`, the statement's: refused unless
/// `format` is in `accepted` and linked in this build ([`LINKED`]); then
/// that format's own decode, at most [`MAX_PROOF_BYTES`], which checks the
/// proof's header against it.
pub fn decode(format: u32, accepted: &[u32], bytes: &[u8]) -> Result<Decoded, Error> {
    if !accepted.contains(&format) {
        return Err(Error::Format);
    }
    let proof = match format {
        masked::FORMAT => masked::decode(bytes)?,
        _ => return Err(Error::Format),
    };
    Ok(Decoded { format, proof })
}

/// Verifies the proof in `bytes` under `format`, the statement's, against
/// the public `words` ([`decode`], then [`Decoded::verify`]), and returns
/// what they state.
pub fn verify(
    format: u32,
    accepted: &[u32],
    bytes: &[u8],
    words: &[u32; PUBLIC_WORDS],
) -> Result<PublicWords, Error> {
    decode(format, accepted, bytes)?.verify(words)
}

/// The QM31 `(w, 0, 0, 0)`.
fn embed(word: u32) -> SecureField {
    SecureField::from(BaseField::from_u32_unchecked(word))
}

fn base_is_canonical(value: &BaseField) -> bool {
    value.0 < P
}

fn secure_is_canonical(value: &SecureField) -> bool {
    value.to_m31_array().iter().all(base_is_canonical)
}

/// Every M31 limb of a proof canonical: its sampled and queried values, its
/// FRI witnesses and last layer.
fn stark_is_canonical(
    stark: &StarkProof<impl stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted>,
) -> bool {
    let fri = &stark.fri_proof;
    stark
        .sampled_values
        .iter()
        .flatten()
        .flatten()
        .all(secure_is_canonical)
        && stark
            .queried_values
            .iter()
            .flatten()
            .flatten()
            .all(base_is_canonical)
        && core::iter::once(&fri.first_layer)
            .chain(&fri.inner_layers)
            .all(|layer| layer.fri_witness.iter().all(secure_is_canonical))
        && fri.last_layer_poly.iter().all(secure_is_canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_words_round_trip() {
        let public = PublicWords {
            program: ProgramId(core::array::from_fn(|i| 1_000 + i as u32)),
            io_hash: core::array::from_fn(|i| (7 * i + 3) as u8),
        };
        let words = public.words();
        assert_eq!(words[8], 3 | 10 << 8);
        assert_eq!(PublicWords::from_words(&words).unwrap(), public);
        let mut wide = words;
        wide[9] = 1 << 16;
        assert!(matches!(
            PublicWords::from_words(&wide),
            Err(Error::PublicWords)
        ));
        let mut beyond = words;
        beyond[0] = P;
        assert!(matches!(
            PublicWords::from_words(&beyond),
            Err(Error::PublicWords)
        ));
    }

    /// A format outside the accepted set, or one this build does not link,
    /// is refused before its bytes are read.
    #[test]
    fn dispatch_is_by_the_accepted_set() {
        assert!(matches!(
            decode(masked::FORMAT, &[], &[]),
            Err(Error::Format)
        ));
        assert!(matches!(decode(40, &[40], &[]), Err(Error::Format)));
        assert!(matches!(
            decode(masked::FORMAT, &[masked::FORMAT], &[]),
            Err(Error::Decode)
        ));
        assert_eq!(LINKED, [39]);
    }
}
