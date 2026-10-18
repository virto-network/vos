//! The final wrap's verifier (`recursion-air.md` §8, `proving.md` §3.5–3.6).
//!
//! A wrap proof is format 28: the recursion AIR's three components at the
//! wrap circuit's log sizes, proved on the Blake2b-256 channel and Merkle
//! trees with blowup 64, 20 queries, PoW 26, interaction PoW 8, FRI fold
//! step 3, a 2^6 last layer and affine DEEP batching. The wrap circuit is
//! pinned by its preprocessed tree's root ([`PREPROCESSED_ROOT`]) and its log
//! sizes ([`LOG_SIZES`]); its 24 public words, the program id (8) and the
//! io-hash's 16 limbs, sit at its addresses 0–23, one word a wire, with zero,
//! one and `u` after them ([`LAYOUT`]).
//!
//! **The transcript**, as `vos-pvm-recair`'s prover runs it:
//! 1. the domain, the format and the PCS configuration, then the log sizes;
//! 2. the preprocessed root, then the main trace's root;
//! 3. the 24 public words, each as the QM31 `(w, 0, 0, 0)`;
//! 4. the interaction PoW nonce;
//! 5. the `Gate` relation's challenges;
//! 6. the three claimed sums, then the interaction root; then Stwo's
//!    protocol.
//!
//! The claimed sums, `u`'s public use and each public word's add to zero:
//! that is what binds the words to the circuit's wires (`vos_pvm_recair_air::gate`).
//!
//! **The proof's shape is checked before any Stwo call** (`check_shape`):
//! the trees' count, every column's sample count, and every M31 limb
//! canonical. Stwo's verifier refuses a malformed FRI proof, Merkle witness
//! or queried-value shape with an error, but it indexes the sampled values by
//! the components' masks, zips the trees' decommitments and queried values
//! with its own trees, and takes the composition tree as the last
//! commitment: each a panic on a proof whose shape is other than the AIR's.
//! Every tree is nonempty, so the Merkle verifier checks each tree's queried
//! values before the DEEP answers read them.
//!
//! **The bytes** ([`decode`]) are one postcard encoding of a [`WrapProof`],
//! at most [`MAX_PROOF_BYTES`] long and with nothing after it. Postcard does
//! not require its varints minimal, so one proof has many encodings: a
//! proof's bytes, or their hash, are no key for it. A venue keys what it has
//! accepted on the statement's id (`vos-statement`), never on the proof.
//!
//! The crate is `no_std`, uses no nightly feature, and builds on stable for
//! x86 and wasm32 and on the pinned nightly for the PVM.

#![no_std]

extern crate alloc;

mod constants;

use alloc::vec::Vec;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2bChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, DeepBatching, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::{Blake2bMerkleChannel, Blake2bMerkleHasher};
use stwo::core::verifier::VerificationError;
use vos_pvm_recair_air::gate::{Layout, public_logup_sum};
use vos_pvm_recair_air::{Components, GateRelation, LOG_CONSTRAINT_EXPANSION, LogSizes};

pub use constants::{LOG_SIZES, PREPROCESSED_ROOT};
pub use vos_pvm_recair_air;

/// The format the wrap's proofs carry (`vos_pvm_proof::format::WRAP`).
pub const FORMAT: u32 = 28;

/// The wrap's public words: the program id's 8, then the io-hash's 16 limbs.
pub const PUBLIC_WORDS: usize = 24;

/// The wrap circuit's reserved wires: its public words at 0–23, then zero,
/// one and `u`.
pub const LAYOUT: Layout = Layout::wrap(PUBLIC_WORDS as u32);

/// Format 28's PCS configuration, affine DEEP batching among it.
pub const CONFIG: PcsConfig = PcsConfig {
    pow_bits: 26,
    fri_config: FriConfig {
        log_last_layer_degree_bound: 6,
        log_blowup_factor: 6,
        n_queries: 20,
        fold_step: 3,
    },
    lifting_log_size: None,
    deep_batching: DeepBatching::Affine,
};

/// Format 28's interaction PoW.
pub const INTERACTION_POW_BITS: u32 = 8;

/// The longest wrap proof [`decode`] reads, in bytes: a bound on a venue's
/// decode and verify work, which a weight is charged by. A wrap proof is
/// 122–125 KB.
pub const MAX_PROOF_BYTES: usize = 256 << 10;

/// The trees a Stwo proof commits: preprocessed, main, interaction and
/// composition.
const TREES: usize = 4;

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
        core::array::from_fn(|i| match i {
            0..8 => self.program[i],
            _ => {
                let limb = i - 8;
                u32::from(self.io_hash[2 * limb]) | u32::from(self.io_hash[2 * limb + 1]) << 8
            }
        })
    }

    /// The statement whose words are `words`: each program word below `p`,
    /// each io-hash limb below 2^16.
    pub fn from_words(words: &[u32; PUBLIC_WORDS]) -> Result<Self, Error> {
        let (program, limbs) = words.split_at(8);
        if program.iter().any(|&word| word >= P) || limbs.iter().any(|&limb| limb >> 16 != 0) {
            return Err(Error::PublicWords);
        }
        Ok(Self {
            program: core::array::from_fn(|i| program[i]),
            io_hash: core::array::from_fn(|i| (limbs[i / 2] >> (8 * (i % 2))) as u8),
        })
    }
}

/// Why a wrap proof is refused.
#[derive(Clone, Debug)]
pub enum Error {
    /// The bytes do not decode as exactly one wrap proof.
    Decode,
    /// The bytes are longer than [`MAX_PROOF_BYTES`].
    Length,
    /// A public word out of its range.
    PublicWords,
    /// Another format, configuration or log sizes.
    Format,
    /// Another circuit: the preprocessed root is not the wrap's.
    Circuit,
    /// The proof's shape is not the wrap AIR's.
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
            Self::Decode => f.write_str("the bytes are not a wrap proof"),
            Self::Length => f.write_str("the bytes are longer than a wrap proof"),
            Self::PublicWords => f.write_str("a public word is out of its range"),
            Self::Format => f.write_str("the proof is not of format 28 at the wrap's log sizes"),
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

/// The wrap proof in `bytes`: at most [`MAX_PROOF_BYTES`], one postcard
/// encoding and nothing after it.
pub fn decode(bytes: &[u8]) -> Result<WrapProof, Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::Length);
    }
    match postcard::take_from_bytes(bytes) {
        Ok((proof, [])) => Ok(proof),
        _ => Err(Error::Decode),
    }
}

/// Verifies the wrap proof in `bytes` ([`decode`]) against the public
/// `words`, and returns the statement they make.
pub fn verify_bytes(bytes: &[u8], words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    verify(decode(bytes)?, words)
}

/// Verifies `proof` against the public `words`, and returns the statement
/// they make: the program id and the io-hash.
pub fn verify(proof: WrapProof, words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    let statement = Statement::from_words(words)?;
    check_header(&proof)?;
    check_shape(&proof.stark_proof)?;
    if !proof.claimed_sums.iter().all(secure_is_canonical) {
        return Err(Error::Noncanonical);
    }
    let stark = &proof.stark_proof;
    if stark.commitments[0] != Blake2bHash(PREPROCESSED_ROOT) {
        return Err(Error::Circuit);
    }

    let [preprocessed, main, interaction] = vos_pvm_recair_air::committed_log_sizes(&LOG_SIZES);
    let channel = &mut Blake2bChannel::default();
    mix_header(channel);
    let scheme = &mut CommitmentSchemeVerifier::<Blake2bMerkleChannel>::new(CONFIG);
    scheme.commit(stark.commitments[0], &preprocessed, channel);
    scheme.commit(stark.commitments[1], &main, channel);
    let public: Vec<SecureField> = words.iter().map(|&word| embed(word)).collect();
    channel.mix_felts(&public);
    if !channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow) {
        return Err(Error::InteractionPow);
    }
    channel.mix_u64(proof.interaction_pow);
    let relation = GateRelation::draw(channel);
    channel.mix_felts(&proof.claimed_sums);
    scheme.commit(stark.commitments[2], &interaction, channel);

    let total = proof.claimed_sums.iter().copied().sum::<SecureField>()
        + public_logup_sum(&relation, LAYOUT.public_terms(public));
    if !total.is_zero() {
        return Err(Error::Logup);
    }

    let components = Components::new(&relation, &LOG_SIZES, &proof.claimed_sums);
    let dyns = components.as_dyn();
    check_samples(&dyns, preprocessed.len(), stark)?;
    stwo::core::verifier::verify(&dyns, channel, scheme, proof.stark_proof)
        .map_err(Error::Stark)?;
    Ok(statement)
}

/// The QM31 `(w, 0, 0, 0)`.
fn embed(word: u32) -> SecureField {
    SecureField::from(BaseField::from_u32_unchecked(word))
}

/// The format, the configuration and the log sizes: the wrap's. A proof's
/// configuration does not carry its DEEP batching, so its batching is not
/// compared.
fn check_header(proof: &WrapProof) -> Result<(), Error> {
    let config = PcsConfig {
        deep_batching: CONFIG.deep_batching,
        ..proof.stark_proof.config
    };
    if proof.format_version != FORMAT || config != CONFIG || proof.log_sizes != LOG_SIZES {
        return Err(Error::Format);
    }
    Ok(())
}

/// A.1's first item: the domain, the format and the PCS configuration, then
/// each component's log size (`vos_pvm_proof::proof::mix_statement_header`).
fn mix_header(channel: &mut impl Channel) {
    let fri = CONFIG.fri_config;
    for word in [
        u64::from_le_bytes(*b"VOS/PVM/"),
        u64::from_le_bytes(*b"STARK/FS"),
        u64::from(FORMAT),
        u64::from(CONFIG.pow_bits),
        fri.n_queries as u64,
        u64::from(fri.log_blowup_factor),
        u64::from(fri.log_last_layer_degree_bound),
        u64::from(fri.fold_step),
        // No lifting log size.
        0,
    ]
    .into_iter()
    .chain(LOG_SIZES.map(u64::from))
    {
        channel.mix_u64(word);
    }
}

fn base_is_canonical(value: &BaseField) -> bool {
    value.0 < P
}

fn secure_is_canonical(value: &SecureField) -> bool {
    value.to_m31_array().iter().all(base_is_canonical)
}

/// The shape every proof of the wrap AIR has, whatever its challenges: four
/// trees of commitments, sampled values, decommitments and queried values,
/// and every M31 limb canonical. The sampled values' columns are checked
/// against the components' masks by `check_samples`.
fn check_shape(stark: &StarkProof<Blake2bMerkleHasher>) -> Result<(), Error> {
    if stark.commitments.len() != TREES {
        return Err(Error::Shape("four commitments"));
    }
    if stark.sampled_values.len() != TREES {
        return Err(Error::Shape("four trees of sampled values"));
    }
    if stark.decommitments.len() != TREES {
        return Err(Error::Shape("four decommitments"));
    }
    if stark.queried_values.len() != TREES {
        return Err(Error::Shape("four trees of queried values"));
    }
    let fri = &stark.fri_proof;
    let canonical = stark
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
        && fri.last_layer_poly.iter().all(secure_is_canonical);
    if !canonical {
        return Err(Error::Noncanonical);
    }
    Ok(())
}

/// Every column's sampled values, one a mask point: the components' masks
/// for the three traces (a preprocessed column one, at the OODS point), and
/// one for each of the composition polynomial's columns.
fn check_samples(
    components: &[&dyn Component],
    n_preprocessed: usize,
    stark: &StarkProof<Blake2bMerkleHasher>,
) -> Result<(), Error> {
    let air = stwo::core::air::Components {
        components: components.to_vec(),
        n_preprocessed_columns: n_preprocessed,
    };
    let max_log_degree_bound = LOG_SIZES.iter().max().copied().unwrap_or(0)
        + LOG_CONSTRAINT_EXPANSION
        - stwo::core::verifier::COMPOSITION_LOG_SPLIT;
    let mut masks = air.mask_points(CirclePoint::zero(), max_log_degree_bound, false);
    masks.push(alloc::vec![alloc::vec![CirclePoint::zero()]; 2 * SECURE_EXTENSION_DEGREE]);
    let matches = masks.len() == stark.sampled_values.len()
        && masks
            .iter()
            .zip(stark.sampled_values.iter())
            .all(|(tree, values)| {
                tree.len() == values.len()
                    && tree
                        .iter()
                        .zip(values)
                        .all(|(points, values)| points.len() == values.len())
            });
    if !matches {
        return Err(Error::Shape("a column's samples are not its mask's"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header is the segment transcript's, on format 28's
    /// configuration and the wrap's log sizes; the constants are format
    /// 28's registry entry.
    #[test]
    fn the_header_and_the_constants_are_format_28s() {
        let wrap = &vos_pvm_proof::format::WRAP;
        assert_eq!(wrap.number, FORMAT);
        assert_eq!(wrap.pcs_config(), CONFIG);
        assert_eq!(wrap.interaction_pow_bits(), INTERACTION_POW_BITS);
        let mut ours = Blake2bChannel::default();
        mix_header(&mut ours);
        let mut theirs = Blake2bChannel::default();
        vos_pvm_proof::proof::mix_statement_header(&mut theirs, FORMAT, &CONFIG, &LOG_SIZES);
        assert_eq!(ours.digest(), theirs.digest());
    }

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
}
