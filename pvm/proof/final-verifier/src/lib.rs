//! The final wrap's verifier (`recursion-air.md` §8, `proving.md` §3.5–3.6,
//! `slice-6-on-chain.md` pins A and B).
//!
//! A wrap proof states the recursion AIR's three components at the wrap
//! circuit's log sizes ([`LOG_SIZES`]), proved on the Blake2b-256 channel
//! and Merkle trees. Its 24 public words, the program id (8) and the
//! io-hash's 16 limbs, sit at the circuit's addresses 0–23, one word a wire,
//! with zero, one and `u` after them ([`LAYOUT`]). The claimed sums, `u`'s
//! public use and each public word's add to zero: that is what binds the
//! words to the circuit's wires (`vos_pvm_recair_air::gate`).
//!
//! **Two formats** (`vos_pvm_proof::format`):
//! - **39** ([`masked`]), the masked wrap: what production venues accept,
//!   and the only one a build links by default. Its bytes are a fixed
//!   layout ([`masked::decode`]): one encoding a proof;
//! - **28** (`unmasked`, under the `test-formats` feature), the unmasked
//!   wrap: the tests' and the fixtures', never a production venue's. Its
//!   bytes are postcard's.
//!
//! **Dispatch is by the statement's format** ([`verify`], [`decode`]): a
//! venue passes the format its statement names and the set it accepts; a
//! format outside the set, or one this build does not link ([`LINKED`]), is
//! refused, and that format's decode checks the proof's own header against
//! it. The format is never read from the proof's bytes, whose encodings
//! differ.
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
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

extern crate alloc;

mod constants;
mod layout;
pub mod masked;
#[cfg(feature = "test-formats")]
pub mod unmasked;

use serde::{Deserialize, Serialize};
use stwo::core::channel::Channel;
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleHasher;
use stwo::core::verifier::VerificationError;
use vos_pvm_recair_air::LogSizes;
use vos_pvm_recair_air::gate::Layout;

pub use constants::{
    LOG_SIZES, MAX_PROOF_BYTES, PREPROCESSED_ROOT, PREPROCESSED_ROOT_39, TREE_WIDTHS,
};
pub use vos_pvm_recair_air;

/// The wrap's public words: the program id's 8, then the io-hash's 16 limbs.
pub const PUBLIC_WORDS: usize = 24;

/// The wrap circuit's reserved wires: its public words at 0–23, then zero,
/// one and `u`.
pub const LAYOUT: Layout = Layout::wrap(PUBLIC_WORDS as u32);

/// The formats this build verifies: 39, and 28 under `test-formats`.
#[cfg(not(feature = "test-formats"))]
pub const LINKED: &[u32] = &[masked::FORMAT];
/// The formats this build verifies: 39, and 28 under `test-formats`.
#[cfg(feature = "test-formats")]
pub const LINKED: &[u32] = &[unmasked::FORMAT, masked::FORMAT];

/// A wrap proof, of either format: its encodings differ, its fields do not.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrapProof {
    pub format_version: u32,
    /// `p2`, `qm31`, `h8`.
    pub log_sizes: LogSizes,
    pub interaction_pow: u64,
    pub claimed_sums: [SecureField; 3],
    pub stark_proof: StarkProof<Blake2bMerkleHasher>,
}

/// What a wrap proof states: the program id and the io-hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub program: [u32; 8],
    pub io_hash: [u8; 32],
}

impl Statement {
    /// Its 24 public words: the program id, then the io-hash's bytes in
    /// pairs, `b0 + 256·b1`.
    pub fn words(&self) -> [u32; PUBLIC_WORDS] {
        let (pairs, _) = self.io_hash.as_chunks::<2>();
        let limbs = pairs
            .iter()
            .map(|&pair| u32::from(u16::from_le_bytes(pair)));
        let mut words = [0; PUBLIC_WORDS];
        for (word, value) in words.iter_mut().zip(self.program.into_iter().chain(limbs)) {
            *word = value;
        }
        words
    }

    /// The statement whose words are `words`: each program word below `p`,
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
            program: *program,
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
    /// returns the statement they make.
    pub fn verify(self, words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
        match self.format {
            masked::FORMAT => masked::verify(self.proof, words),
            #[cfg(feature = "test-formats")]
            unmasked::FORMAT => unmasked::verify(self.proof, words),
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
        #[cfg(feature = "test-formats")]
        unmasked::FORMAT => unmasked::decode(bytes)?,
        _ => return Err(Error::Format),
    };
    Ok(Decoded { format, proof })
}

/// Verifies the proof in `bytes` under `format`, the statement's, against
/// the public `words` ([`decode`], then [`Decoded::verify`]), and returns
/// the statement they make.
pub fn verify(
    format: u32,
    accepted: &[u32],
    bytes: &[u8],
    words: &[u32; PUBLIC_WORDS],
) -> Result<Statement, Error> {
    decode(format, accepted, bytes)?.verify(words)
}

/// The QM31 `(w, 0, 0, 0)`.
fn embed(word: u32) -> SecureField {
    SecureField::from(BaseField::from_u32_unchecked(word))
}

/// A.1's first item: the domain, the format and the PCS configuration, then
/// each component's log size (`vos_pvm_proof::proof::mix_statement_header`).
pub fn mix_header(channel: &mut impl Channel, format: u32, config: &PcsConfig, log_sizes: &[u32]) {
    let fri = config.fri_config;
    for word in [
        u64::from_le_bytes(*b"VOS/PVM/"),
        u64::from_le_bytes(*b"STARK/FS"),
        u64::from(format),
        u64::from(config.pow_bits),
        fri.n_queries as u64,
        u64::from(fri.log_blowup_factor),
        u64::from(fri.log_last_layer_degree_bound),
        u64::from(fri.fold_step),
    ] {
        channel.mix_u64(word);
    }
    match config.lifting_log_size {
        None => channel.mix_u64(0),
        Some(lifting) => {
            channel.mix_u64(1);
            channel.mix_u64(u64::from(lifting));
        }
    }
    for &log_size in log_sizes {
        channel.mix_u64(u64::from(log_size));
    }
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
    fn a_statements_words_round_trip() {
        let statement = Statement {
            program: core::array::from_fn(|i| 1_000 + i as u32),
            io_hash: core::array::from_fn(|i| (7 * i + 3) as u8),
        };
        let words = statement.words();
        assert_eq!(words[8], 3 | 10 << 8);
        assert_eq!(Statement::from_words(&words).unwrap(), statement);
        let mut wide = words;
        wide[9] = 1 << 16;
        assert!(matches!(
            Statement::from_words(&wide),
            Err(Error::PublicWords)
        ));
        let mut beyond = words;
        beyond[0] = P;
        assert!(matches!(
            Statement::from_words(&beyond),
            Err(Error::PublicWords)
        ));
    }

    /// Format 39's preprocessed root is format 28's (pin A): its columns at
    /// `n + 1` under blowup 32 are format 28's at `n + 6`.
    #[test]
    fn the_masked_preprocessed_root_is_format_28s() {
        assert_eq!(PREPROCESSED_ROOT_39, PREPROCESSED_ROOT);
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
        assert!(LINKED.contains(&masked::FORMAT));
        #[cfg(not(feature = "test-formats"))]
        assert_eq!(LINKED, [39]);
    }
}
