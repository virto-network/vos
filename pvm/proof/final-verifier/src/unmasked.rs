//! `format::WRAP`, the unmasked wrap: the tests' and the fixtures' format, linked
//! only under the `test-formats` feature; no production venue accepts it.
//!
//! The recursion AIR's three components at the wrap circuit's log sizes,
//! proved on the Blake2b-256 channel and Merkle trees with blowup 64, 20
//! queries, PoW 26, interaction PoW 8, FRI fold step 3, a 2^6 last layer and
//! affine DEEP batching. The wrap circuit is pinned by its preprocessed
//! tree's root ([`crate::PREPROCESSED_ROOT`]) and its log sizes. The
//! transcript is the recursion AIR's (`vos_pvm_recair_air::transcript`), its
//! public values the 24 words, each the QM31 `(w, 0, 0, 0)`.
//!
//! **The shape is checked before any Stwo call** (`check_shape`): the
//! trees' count, every column's sample count, and every M31 limb canonical.
//! Every tree is nonempty, so the Merkle verifier checks each tree's queried
//! values before the DEEP answers read them.
//!
//! **The bytes** ([`decode`]) are one postcard encoding of a [`WrapProof`],
//! at most [`MAX_PROOF_BYTES`] long and with nothing after it, its format
//! word 28. Postcard does not require its varints minimal, so one proof has
//! many encodings.

use alloc::vec::Vec;

use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2bChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, DeepBatching, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::{Blake2bMerkleChannel, Blake2bMerkleHasher};
use vos_pvm_recair_air::gate::public_logup_sum;
use vos_pvm_recair_air::transcript::{Prefix, replay_prefix};
use vos_pvm_recair_air::{Components, LOG_CONSTRAINT_EXPANSION};

use crate::masked::TREES;
use crate::{
    Error, LAYOUT, LOG_SIZES, MAX_PROOF_BYTES, PREPROCESSED_ROOT, PUBLIC_WORDS, Statement,
    WrapProof, embed, mix_header, secure_is_canonical, stark_is_canonical,
};

/// The format the unmasked wrap's proofs carry (`vos_pvm_proof::format::WRAP`).
pub const FORMAT: u32 = 28;

/// `format::WRAP`'s PCS configuration, affine DEEP batching among it.
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

/// `format::WRAP`'s interaction PoW.
pub const INTERACTION_POW_BITS: u32 = 8;

/// The `format::WRAP` proof in `bytes`: at most [`MAX_PROOF_BYTES`], its format
/// word 28, one postcard encoding and nothing after it.
pub fn decode(bytes: &[u8]) -> Result<WrapProof, Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::Length);
    }
    match postcard::take_from_bytes::<u32>(bytes) {
        Ok((FORMAT, _)) => {}
        Ok(_) => return Err(Error::Format),
        Err(_) => return Err(Error::Decode),
    }
    match postcard::take_from_bytes(bytes) {
        Ok((proof, [])) => Ok(proof),
        _ => Err(Error::Decode),
    }
}

/// Verifies the `format::WRAP` proof in `bytes` ([`decode`]) against the public
/// `words`.
pub fn verify_bytes(bytes: &[u8], words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    verify(decode(bytes)?, words)
}

/// Verifies a `format::WRAP` `proof` against the public `words`, and returns the
/// statement they make: the program id and the io-hash.
pub fn verify(proof: WrapProof, words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    let statement = Statement::from_words(words)?;
    check_header(&proof)?;
    check_shape(&proof.stark_proof)?;
    if !proof.claimed_sums.iter().all(secure_is_canonical) {
        return Err(Error::Noncanonical);
    }
    let stark = &proof.stark_proof;
    let &[preprocessed, main, interaction, _] = stark.commitments.as_slice() else {
        return Err(Error::Shape("four commitments"));
    };
    if preprocessed != Blake2bHash(PREPROCESSED_ROOT) {
        return Err(Error::Circuit);
    }

    let log_sizes = vos_pvm_recair_air::committed_log_sizes(&LOG_SIZES);
    let channel = &mut Blake2bChannel::default();
    mix_header(channel, FORMAT, &CONFIG, &LOG_SIZES);
    let scheme = &mut CommitmentSchemeVerifier::<Blake2bMerkleChannel>::new(CONFIG);
    let public: Vec<SecureField> = words.iter().map(|&word| embed(word)).collect();
    let prefix = Prefix {
        roots: [preprocessed, main, interaction],
        log_sizes: &log_sizes,
        public: &public,
        claimed_sums: &proof.claimed_sums,
    };
    let relation = replay_prefix(channel, scheme, prefix, |channel| {
        if !channel.verify_pow_nonce(INTERACTION_POW_BITS, proof.interaction_pow) {
            return Err(Error::InteractionPow);
        }
        channel.mix_u64(proof.interaction_pow);
        Ok(())
    })?;

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "QM31's addition is modular: it neither overflows nor panics"
    )]
    let total = proof.claimed_sums.iter().copied().sum::<SecureField>()
        + public_logup_sum(&relation, LAYOUT.public_terms(public));
    if !total.is_zero() {
        return Err(Error::Logup);
    }

    let components = Components::new(&relation, &LOG_SIZES, &proof.claimed_sums);
    let dyns = components.as_dyn();
    check_samples(&dyns, log_sizes[0].len(), stark)?;
    stwo::core::verifier::verify(&dyns, channel, scheme, proof.stark_proof)
        .map_err(Error::Stark)?;
    Ok(statement)
}

/// The format, the configuration and the log sizes: `format::WRAP`'s. A proof's
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
    if !stark_is_canonical(stark) {
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
    let max_log_degree_bound = LOG_SIZES
        .iter()
        .max()
        .and_then(|log_size| log_size.checked_add(LOG_CONSTRAINT_EXPANSION))
        .and_then(|bound| bound.checked_sub(stwo::core::verifier::COMPOSITION_LOG_SPLIT))
        .ok_or(Error::Shape("the composition's degree bound"))?;
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

    /// The header is the segment transcript's, on `format::WRAP`'s
    /// configuration and the wrap's log sizes; the constants are format
    /// 28's registry entry.
    #[test]
    fn the_header_and_the_constants_are_format_28s() {
        let wrap = &vos_pvm_proof::format::WRAP;
        assert_eq!(wrap.number, FORMAT);
        assert_eq!(wrap.pcs_config(), CONFIG);
        assert_eq!(wrap.interaction_pow_bits(), INTERACTION_POW_BITS);
        assert_eq!(wrap.bytes, vos_pvm_proof::format::ProofBytes::Postcard);
        let mut ours = Blake2bChannel::default();
        mix_header(&mut ours, FORMAT, &CONFIG, &LOG_SIZES);
        let mut theirs = Blake2bChannel::default();
        vos_pvm_proof::proof::mix_statement_header(&mut theirs, FORMAT, &CONFIG, &LOG_SIZES);
        assert_eq!(ours.digest(), theirs.digest());
    }
}
