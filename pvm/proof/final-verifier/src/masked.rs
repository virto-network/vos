//! The masked wrap's verifier: format 39 (`vos_pvm_recair_air::format::MASKED_WRAP`,
//! the registry's one entry), its pins and the recursion AIR's wrap
//! verified on the Blake2b-256 channel ([`verify`]), through the masked
//! verifier ([`crate::masking::verify_masked`]).
//!
//! **The trust boundary:** three facts the verifier leaves to Stwo, each
//! pinned by the format and tested.
//! - `verify_values` zips the sample points with the sampled values, and
//!   its trees with the decommitments and queried values: the trees'
//!   widths ([`crate::TREE_WIDTHS`]) and counts, which `check_shape`
//!   holds every proof to first;
//! - `verify_values` takes FRI's degree bound as the last committed tree's
//!   height less the blowup, so the composition tree must be the last
//!   commitment and the tallest ([`LOG_DEGREE_BOUND`], 17): held by
//!   `committed_log_sizes`, which lays it out last, and by the test that the
//!   tallest committed column is at 17;
//! - `FriVerifier::commit` derives FRI's rounds from that bound
//!   ([`FRI_ROUNDS`], `[3, 3, 3, 2]`), which [`crate::masking::fri_rounds`] derives as it
//!   does and the security count (`vos_pvm_proof::security`) is taken at.
//!
//! And the shape is tied to the transcript: the values the verifier's own
//! sample points batch are the format's ([`DEEP_VALUES`], 538, the
//! reference shape's `B`).

use alloc::vec::Vec;

use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use vos_pvm_recair_air::GateRelation;
use vos_pvm_recair_air::format::{self as registry, MASKED_WRAP_MASKING};
use vos_pvm_recair_air::gate::public_logup_sum;
use vos_pvm_recair_air::wrap::WrapComponents;

use crate::masking::{Claim, MaskedFormat, verify_masked};
use crate::{
    Error, LAYOUT, LOG_SIZES, PREPROCESSED_ROOT_39, PUBLIC_WORDS, PublicWords, TREE_WIDTHS,
    WrapProof, embed,
};

/// The masked wrap's format number, the registry entry's.
pub const FORMAT: u32 = registry::MASKED_WRAP.number;

/// The masked wrap's PCS configuration, the registry entry's: blowup 32, 16
/// queries, PoW 26, FRI fold step 3, a 2^6 last layer, affine DEEP
/// batching.
pub const CONFIG: PcsConfig = registry::MASKED_WRAP.pcs_config();

/// The values `format::MASKED_WRAP`'s DEEP quotient batches:
/// `(57 + 373 + 40 + 4 + 8) + 2·(16 + 3·4)`, a twice-sampled column batching
/// a third, its periodicity value (`MASKED_WRAP_REFERENCE.sampled_values`).
pub const DEEP_VALUES: usize = 538;

/// FRI's degree bound under `format::MASKED_WRAP`: the composition's,
/// committed whole at `m + 2` for the wrap's tallest component of `2^15` rows.
pub const LOG_DEGREE_BOUND: u32 = 17;

/// FRI's folding rounds at `format::MASKED_WRAP`'s degree bound,
/// 2^[`LOG_DEGREE_BOUND`], to its 2^6 last layer: the first with the circle
/// fold in it ([`fri_rounds`](crate::masking::fri_rounds)).
pub const FRI_ROUNDS: [u32; 4] = [3, 3, 3, 2];

/// `format::MASKED_WRAP`'s samples of column `column` of tree `tree`, as its
/// sample points lay them out: every preprocessed column once; in the main
/// tree the 16 `p2` columns its last round also reads at the previous row
/// (every other one from 269) twice, the rest once, the 8 salts never; in
/// the interaction tree each component's running sum (4 columns) twice, the
/// rest once, the salts never; in the composition tree its 4 coordinates and
/// `R`'s 8 once, the salts never. The decode reads exactly these;
/// `check_shape` holds every proof to the sample points themselves.
pub const fn samples(tree: usize, column: usize) -> usize {
    match (tree, column) {
        (0, 0..57) => 1,
        (1, 269..301) if column & 1 == 1 => 2,
        (1, 0..373) => 1,
        (2, 8..12 | 20..24 | 36..40) => 2,
        (2, 0..40) => 1,
        (3, 0..12) => 1,
        _ => 0,
    }
}

/// The masked wrap's format as its verifier pins it, every field the
/// registry entry's or the wrap circuit's.
pub const MASKED_WRAP: MaskedFormat<'static> = MaskedFormat {
    number: FORMAT,
    config: CONFIG,
    interaction_pow_bits: registry::MASKED_WRAP.params.interaction_pow_bits,
    masking: MASKED_WRAP_MASKING,
    log_sizes: &LOG_SIZES,
    tree_widths: TREE_WIDTHS,
    deep_values: DEEP_VALUES,
    program: &[],
};

/// The `format::MASKED_WRAP` proof in `bytes`: at most
/// [`crate::MAX_PROOF_BYTES`], its fixed layout read whole, its header the
/// format's, every count its pin or within its bound, nothing after it.
pub fn decode(bytes: &[u8]) -> Result<WrapProof, Error> {
    crate::layout::decode(bytes)
}

/// `proof`'s fixed layout: what the prover emits for `format::MASKED_WRAP`,
/// and the one encoding [`decode`] reads; `None` for a proof the layout
/// cannot hold (a column of other samples than [`samples`], a tree whose
/// queried columns differ in length), which no verifier would accept.
pub fn encode(proof: &WrapProof) -> Option<Vec<u8>> {
    crate::layout::encode(proof)
}

/// Verifies the `format::MASKED_WRAP` proof in `bytes` ([`decode`]) against
/// the public `words`.
pub fn verify_bytes(bytes: &[u8], words: &[u32; PUBLIC_WORDS]) -> Result<PublicWords, Error> {
    verify(decode(bytes)?, words)
}

/// Verifies a `format::MASKED_WRAP` proof of the wrap circuit against the
/// public `words`, and returns what they state: the program id and
/// the io-hash.
pub fn verify(proof: WrapProof, words: &[u32; PUBLIC_WORDS]) -> Result<PublicWords, Error> {
    verify_under(&MASKED_WRAP, &PREPROCESSED_ROOT_39, proof, words)
}

/// [`verify`] under `format`'s pins and the circuit `preprocessed_root`: a
/// verifier pinning other salts, `R` or widths refuses `MASKED_WRAP`'s proofs.
/// A test seam (`other-pins`): a production verifier pins
/// [`MASKED_WRAP`] and [`PREPROCESSED_ROOT_39`], and takes neither.
#[cfg(feature = "other-pins")]
pub fn verify_with(
    format: &MaskedFormat<'_>,
    preprocessed_root: &[u8; 32],
    proof: WrapProof,
    words: &[u32; PUBLIC_WORDS],
) -> Result<PublicWords, Error> {
    verify_under(format, preprocessed_root, proof, words)
}

fn verify_under(
    format: &MaskedFormat<'_>,
    preprocessed_root: &[u8; 32],
    proof: WrapProof,
    words: &[u32; PUBLIC_WORDS],
) -> Result<PublicWords, Error> {
    let statement = PublicWords::from_words(words)?;
    if proof.format_version != format.number || proof.log_sizes[..] != *format.log_sizes {
        return Err(Error::Format);
    }
    let public: Vec<SecureField> = words.iter().map(|&word| embed(word)).collect();
    let public_sum = |relation: &GateRelation| {
        public_logup_sum(relation, LAYOUT.public_terms(public.iter().copied()))
    };
    let layout = WrapComponents::layout(&proof.log_sizes);
    verify_masked::<Blake2bMerkleChannel, WrapComponents>(
        format,
        &Claim {
            log_sizes: &proof.log_sizes,
            circuit: Blake2bHash(*preprocessed_root),
            public: &public,
            public_sum: &public_sum,
            bound_sums: &|_, _| true,
            interaction_pow: proof.interaction_pow,
            claimed_sums: &proof.claimed_sums,
        },
        &layout,
        proof.stark_proof,
    )?;
    Ok(statement)
}

#[cfg(test)]
mod tests {
    use super::*;

    use stwo::core::circle::CirclePoint;
    use stwo::core::fri::FriConfig;
    use stwo::core::pcs::DeepBatching;
    use vos_pvm_recair_air::format::ProofBytes;
    use vos_pvm_recair_air::masking::{committed_log_sizes, sample_points};

    use crate::masking::{fri_rounds, shape_of};

    /// The wrap's set at the masked wrap's masking: the trees' widths
    /// 57, 381, 48 and 20 and 538 DEEP values, as pinned; the composition
    /// tree the last and at FRI's degree bound, the tallest; every column's
    /// samples [`samples`]'.
    #[test]
    fn the_pinned_shape_is_the_wrap_components() {
        let layout = WrapComponents::layout(&LOG_SIZES);
        let masking = &MASKED_WRAP_MASKING;
        assert_eq!(shape_of(&layout, masking), Some((TREE_WIDTHS, DEEP_VALUES)));
        let trees = committed_log_sizes(&layout, masking).unwrap();
        assert_eq!(trees.iter().flatten().max(), Some(&LOG_DEGREE_BOUND));
        assert!(trees[3].iter().all(|&level| level == LOG_DEGREE_BOUND));
        let points = sample_points(&layout, CirclePoint::zero(), masking).unwrap();
        for (tree, columns) in points.iter().enumerate() {
            for (column, points) in columns.iter().enumerate() {
                assert_eq!(
                    points.len(),
                    samples(tree, column),
                    "tree {tree}, column {column}"
                );
            }
            assert_eq!(samples(tree, columns.len()), 0, "past tree {tree}");
        }
    }

    /// FRI's rounds at 2^17 to a 2^6 last layer in steps of 3: `[3, 3, 3,
    /// 2]`, as `FriVerifier::commit` folds; none where commit refuses every
    /// proof.
    #[test]
    fn fri_rounds_fold_as_commit_does() {
        assert_eq!(
            fri_rounds(LOG_DEGREE_BOUND, &CONFIG.fri_config).unwrap(),
            FRI_ROUNDS
        );
        let config = |fold_step, log_last_layer_degree_bound| FriConfig {
            fold_step,
            log_last_layer_degree_bound,
            ..CONFIG.fri_config
        };
        assert_eq!(fri_rounds(15, &config(3, 6)).unwrap(), [3, 3, 3]);
        assert_eq!(fri_rounds(9, &config(3, 6)).unwrap(), [3]);
        assert_eq!(fri_rounds(8, &config(3, 6)), None);
        assert_eq!(fri_rounds(4, &config(1, 0)).unwrap(), [1; 4]);
        assert_eq!(fri_rounds(4, &config(0, 0)), None);
    }

    /// The masked wrap's pins, as numbers: format 39, blowup 32, 24
    /// queries, PoW 26, fold step 3, a 2^6 last layer, affine batching, 8
    /// bits of interaction PoW, 8 salts, an `R` of 8, `h = 256`, its bytes a
    /// fixed layout. A change to the registry entry that moves the venue's
    /// verifier fails here.
    #[test]
    fn the_masked_wrap_is_format_39s() {
        assert_eq!(
            (
                MASKED_WRAP.number,
                MASKED_WRAP.config,
                MASKED_WRAP.interaction_pow_bits,
                MASKED_WRAP.masking,
            ),
            (
                39,
                PcsConfig {
                    pow_bits: 26,
                    fri_config: FriConfig {
                        log_last_layer_degree_bound: 6,
                        log_blowup_factor: 5,
                        n_queries: 16,
                        fold_step: 3,
                    },
                    lifting_log_size: None,
                    deep_batching: DeepBatching::Affine,
                },
                8,
                vos_pvm_recair_air::format::Masking {
                    salt_columns: 8,
                    fri_mask_columns: 8,
                    log_mask_rows: 8,
                },
            )
        );
        assert_eq!(registry::MASKED_WRAP.bytes, ProofBytes::FixedLayout);
        assert_eq!(MASKED_WRAP.log_sizes, LOG_SIZES);
    }
}
