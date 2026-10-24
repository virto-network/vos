//! The masked wrap's verifier: `format::MASKED_WRAP` (pin A), its transcript pin B's,
//! over any masked component set and Merkle channel ([`verify_masked`]),
//! the recursion AIR's wrap on the Blake2b-256 channel its production use
//! ([`verify`]).
//!
//! **The transcript** (pin B): the header (the format's number and
//! configuration, the log sizes); the preprocessed root (columns at
//! `n + 1`, unsalted); the main root (masked columns, blinding columns,
//! salts); the public values; the interaction PoW; the set's relations, then
//! the blinding relation; the blinded claimed sums; the interaction root;
//! the composition coefficient; the composition tree's root (the whole
//! composition, the FRI mask `R`, salts); the out-of-domain point `z`; then
//! Stwo's PCS (`CommitmentSchemeVerifier::{commit, verify_values}`). Never
//! `stwo::core::verifier::verify`, whose composition split is hardcoded
//! (DIVERGENCE-004).
//!
//! **Everything is the format's** ([`MaskedFormat`]): the configuration
//! and its DEEP batching, the log sizes, the salts, `R` and `h`, the trees'
//! widths and the values the DEEP quotient batches. None is read from the
//! proof, whose own header is checked against them.
//!
//! **Before any Stwo call** ([`check_shape`]): the proof's log sizes and
//! configuration the format's (before the component set is built at them);
//! the set's trees the format's widths; four trees of commitments,
//! decommitments, sampled and queried values, each tree of the format's
//! width; every column's samples one for each of its sample points (the
//! composition tree's 4 coordinates and `R`'s columns one each, its salts
//! none); FRI's layers the rounds its degree bound folds in, its last layer
//! the format's; every M31 limb canonical.
//!
//! **The trust boundary:** three facts the verifier leaves to Stwo, each
//! pinned by the format and tested.
//! - `verify_values` zips the sample points with the sampled values, and
//!   its trees with the decommitments and queried values: the trees'
//!   widths ([`crate::TREE_WIDTHS`]) and counts, which [`check_shape`]
//!   holds every proof to first;
//! - `verify_values` takes FRI's degree bound as the last committed tree's
//!   height less the blowup, so the composition tree must be the last
//!   commitment and the tallest ([`LOG_DEGREE_BOUND`], 17): held by
//!   `committed_log_sizes`, which lays it out last, and by the test that the
//!   tallest committed column is at 17;
//! - `FriVerifier::commit` derives FRI's rounds from that bound
//!   ([`FRI_ROUNDS`], `[3, 3, 3, 2]`), which [`fri_rounds`] derives as it
//!   does and the security count (`vos_pvm_proof::security`) is taken at.
//!
//! And the shape is tied to the transcript: the values the verifier's own
//! sample points batch are the format's ([`DEEP_VALUES`], 538, the
//! reference shape's `B`).

use alloc::vec::Vec;

use num_traits::Zero;
use stwo::core::ColumnVec;
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo::core::pcs::{CommitmentSchemeVerifier, DeepBatching, PcsConfig, TreeVec};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::VerificationError;
use vos_pvm_recair_air::GateRelation;
use vos_pvm_recair_air::gate::public_logup_sum;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskPins, MaskedComponent, MaskedComponents, WrapComponents, air_log_size,
    committed_log_sizes, composition_oods_eval, sample_points, sample_points_from_zero,
};

use crate::{
    Error, LAYOUT, LOG_SIZES, PREPROCESSED_ROOT_39, PUBLIC_WORDS, Statement, TREE_WIDTHS,
    WrapProof, embed, mix_header, secure_is_canonical, stark_is_canonical,
};

/// The trees a masked proof commits: preprocessed, main, interaction,
/// composition.
pub const TREES: usize = 4;

/// The masked wrap's format number (`vos_pvm_proof::format::MASKED_WRAP`).
pub const FORMAT: u32 = 39;

/// `format::MASKED_WRAP`'s PCS configuration: blowup 32, 24 queries, PoW 26, FRI fold
/// step 3, a 2^6 last layer, affine DEEP batching.
pub const CONFIG: PcsConfig = PcsConfig {
    pow_bits: 26,
    fri_config: FriConfig {
        log_last_layer_degree_bound: 6,
        log_blowup_factor: 5,
        n_queries: 24,
        fold_step: 3,
    },
    lifting_log_size: None,
    deep_batching: DeepBatching::Affine,
};

/// `format::MASKED_WRAP`'s interaction PoW.
pub const INTERACTION_POW_BITS: u32 = 8;

/// `format::MASKED_WRAP`'s trees beside the AIR's columns: 8 salt columns a salted tree,
/// an `R` of 8 columns.
pub const PINS: MaskPins = MaskPins {
    salt_columns: 8,
    fri_mask_columns: 8,
};

/// `format::MASKED_WRAP`'s `log2 h`: the prover's randomizer, 256 coefficients a column.
/// The verifier reads no mask; pinned with the format, for its registry
/// entry.
pub const LOG_MASK_ROWS: u32 = 8;

/// The values `format::MASKED_WRAP`'s DEEP quotient batches: `(57 + 373 + 40 + 4 + 8) +
/// 2·(16 + 3·4)`, a twice-sampled column batching a third, its periodicity
/// value (`MASKED_WRAP_REFERENCE.sampled_values`).
pub const DEEP_VALUES: usize = 538;

/// FRI's degree bound under `format::MASKED_WRAP`: the composition's, committed whole
/// at `m + 2` for the wrap's tallest component of `2^15` rows.
pub const LOG_DEGREE_BOUND: u32 = 17;

/// FRI's folding rounds at `format::MASKED_WRAP`'s degree bound, 2^[`LOG_DEGREE_BOUND`],
/// to its 2^6 last layer: the first with the circle fold in it
/// ([`fri_rounds`]).
pub const FRI_ROUNDS: [u32; 4] = [3, 3, 3, 2];

/// `format::MASKED_WRAP`'s samples of column `column` of tree `tree`, as its sample
/// points lay them out: every preprocessed column once; in the main tree
/// the 16 `p2` columns its last round also reads at the previous row (every
/// other one from 269) twice, the rest once, the 8 salts never; in the
/// interaction tree each component's running sum (4 columns) twice, the
/// rest once, the salts never; in the composition tree its 4 coordinates
/// and `R`'s 8 once, the salts never. The decode reads exactly these;
/// [`check_shape`] holds every proof to the sample points themselves.
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

/// A masked format, as its verifier pins it: nothing here is read from a
/// proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskedFormat<'a> {
    pub number: u32,
    /// Its configuration, its DEEP batching among it.
    pub config: PcsConfig,
    pub interaction_pow_bits: u32,
    /// Its salt and `R` columns.
    pub pins: MaskPins,
    /// `log2 h`, the prover's.
    pub log_mask_rows: u32,
    /// Each component's log size.
    pub log_sizes: &'a [u32],
    /// Each tree's columns.
    pub tree_widths: [usize; TREES],
    /// The values its DEEP quotient batches.
    pub deep_values: usize,
}

/// `format::MASKED_WRAP`, the masked wrap (pin A).
pub const MASKED_WRAP: MaskedFormat<'static> = MaskedFormat {
    number: FORMAT,
    config: CONFIG,
    interaction_pow_bits: INTERACTION_POW_BITS,
    pins: PINS,
    log_mask_rows: LOG_MASK_ROWS,
    log_sizes: &LOG_SIZES,
    tree_widths: TREE_WIDTHS,
    deep_values: DEEP_VALUES,
};

/// The sample points' DEEP values: one a sample, and a third for a
/// twice-sampled column, its periodicity value.
fn deep_values(points: &TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>) -> usize {
    points
        .iter()
        .flatten()
        .map(|column| deep_values_of_column(column.len()))
        .sum()
}

/// A component set's trees' widths and the values its DEEP quotient
/// batches, laid out by `pins`: what a masked format pins as its
/// `tree_widths` and `deep_values`. `None` when the set's masks do not fit
/// its trees, or it commits other than four.
pub fn shape_of(
    layout: &impl MaskedComponents,
    pins: &MaskPins,
) -> Option<([usize; TREES], usize)> {
    let points = sample_points(layout, CirclePoint::zero(), pins)?;
    let widths: [usize; TREES] = points
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    Some((widths, deep_values(&points)))
}

/// The folding steps `FriVerifier::commit` takes from a committed degree
/// bound `2^log_degree_bound` to the last layer: the first layer's
/// `fold_step` (the circle fold among it), then `fold_step` an inner layer,
/// the last inner layer what remains. Commit refuses a proof with another
/// count of layers; `None` where it refuses every proof.
pub fn fri_rounds(log_degree_bound: u32, config: &FriConfig) -> Option<Vec<u32>> {
    let step = config.fold_step;
    if step == 0 {
        return None;
    }
    let mut remaining = log_degree_bound
        .checked_sub(step)?
        .checked_sub(config.log_last_layer_degree_bound)?;
    let mut rounds = alloc::vec![step];
    while remaining > 0 {
        let fold = step.min(remaining);
        rounds.push(fold);
        remaining = remaining.checked_sub(fold)?;
    }
    Some(rounds)
}

/// What a masked proof claims beside its STARK proof.
pub struct Claim<'a, R, Hash> {
    /// Each component's log size, the proof's: the format's or refused.
    pub log_sizes: &'a [u32],
    /// The preprocessed root the circuit pins; `None` for a set whose
    /// circuit is not checked.
    pub circuit: Option<Hash>,
    /// The values mixed after the main tree's root.
    pub public: &'a [SecureField],
    /// The public terms' logup sum under the relations, which the claimed
    /// sums must cancel; `None` for a set whose sums are not checked.
    pub public_sum: Option<&'a dyn Fn(&R) -> SecureField>,
    pub interaction_pow: u64,
    pub claimed_sums: &'a [SecureField],
}

/// Each column of `values` holds one value for each of its sample points.
fn samples_fit<P, V>(
    points: &TreeVec<ColumnVec<Vec<P>>>,
    values: &TreeVec<ColumnVec<Vec<V>>>,
) -> bool {
    points.len() == values.len()
        && points.iter().zip(values.iter()).all(|(points, values)| {
            points.len() == values.len()
                && points
                    .iter()
                    .zip(values)
                    .all(|(points, values)| points.len() == values.len())
        })
}

/// The shape every proof of `format` has, whatever its challenges, before
/// any Stwo call: four trees of commitments, decommitments, sampled and
/// queried values; each tree's sampled and queried columns its committed
/// columns (`trees`), each column's samples one for each of its sample
/// points (`points`, at any point); FRI's inner layers the rounds its degree
/// bound folds in after the first, its last layer the format's degree; every
/// M31 limb canonical.
pub fn check_shape<H: MerkleHasherLifted>(
    format: &MaskedFormat<'_>,
    trees: &TreeVec<Vec<u32>>,
    points: &TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    stark: &StarkProof<H>,
) -> Result<(), Error> {
    if [
        stark.commitments.len(),
        stark.decommitments.len(),
        stark.sampled_values.len(),
        stark.queried_values.len(),
        trees.len(),
        points.len(),
    ] != [TREES; 6]
    {
        return Err(Error::Shape("four trees"));
    }
    if trees.iter().map(Vec::len).ne(format.tree_widths) {
        return Err(Error::Shape(
            "the component set's trees are not the format's",
        ));
    }
    if !samples_fit(points, &stark.sampled_values) {
        return Err(Error::Shape(
            "a column's samples are not its sample points'",
        ));
    }
    if stark
        .queried_values
        .iter()
        .map(Vec::len)
        .ne(format.tree_widths)
    {
        return Err(Error::Shape("a tree's queried columns are not its columns"));
    }
    let fri = &format.config.fri_config;
    let degree_bound = trees.iter().flatten().max().copied().unwrap_or(0);
    let rounds = fri_rounds(degree_bound, fri).ok_or(Error::Shape("FRI's rounds"))?;
    if Some(stark.fri_proof.inner_layers.len()) != rounds.len().checked_sub(1) {
        return Err(Error::Shape("FRI's layers are not its rounds"));
    }
    if stark.fri_proof.last_layer_poly.checked_log_size() != Some(fri.log_last_layer_degree_bound) {
        return Err(Error::Shape("FRI's last layer is not the format's degree"));
    }
    if !stark_is_canonical(stark) {
        return Err(Error::Noncanonical);
    }
    Ok(())
}

/// The transcript replayed to the DEEP coefficients: the channel before
/// `verify_values` mixes the samples, the scheme and the sample points.
pub struct Replayed<MC: MerkleChannel> {
    pub channel: MC::C,
    pub scheme: CommitmentSchemeVerifier<MC>,
    pub points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
}

/// `claim`'s transcript under `format` replayed over `proof`, the component
/// set `C` laid out as `layout` (at the format's log sizes, any relations),
/// every check before Stwo's PCS done: the header, the shape
/// ([`check_shape`]), the circuit, the interaction PoW, the logup sums, the
/// sample points' DEEP values and the composition at the out-of-domain
/// point. The set is laid out once: its sample points made at zero for the
/// shape and moved to the out-of-domain point, its constraints evaluated
/// under the drawn relations by binding them to `layout`
/// ([`MaskedComponents::bind`]).
pub fn replay<MC: MerkleChannel, C: MaskedComponents>(
    format: &MaskedFormat<'_>,
    claim: &Claim<'_, C::Relations, <MC::H as MerkleHasherLifted>::Hash>,
    layout: &C,
    proof: &StarkProof<MC::H>,
) -> Result<Replayed<MC>, Error> {
    let config = PcsConfig {
        deep_batching: format.config.deep_batching,
        ..proof.config
    };
    if claim.log_sizes != format.log_sizes
        || layout.log_sizes() != format.log_sizes
        || config != format.config
    {
        return Err(Error::Format);
    }
    let trees = committed_log_sizes(layout, &format.pins)
        .ok_or(Error::Shape("the component set's trees"))?;
    let mut points = sample_points(layout, CirclePoint::zero(), &format.pins)
        .ok_or(Error::Shape("the component set's sample points"))?;
    check_shape(format, &trees, &points, proof)?;
    let [
        preprocessed_tree,
        main_tree,
        interaction_tree,
        composition_tree,
    ] = trees.as_slice()
    else {
        return Err(Error::Shape("four trees"));
    };
    let &[
        preprocessed_root,
        main_root,
        interaction_root,
        composition_root,
    ] = proof.commitments.as_slice()
    else {
        return Err(Error::Shape("four commitments"));
    };
    if !claim.claimed_sums.iter().all(secure_is_canonical) {
        return Err(Error::Noncanonical);
    }
    if claim.circuit.is_some_and(|root| preprocessed_root != root) {
        return Err(Error::Circuit);
    }

    let mut channel = MC::C::default();
    mix_header(
        &mut channel,
        format.number,
        &format.config,
        format.log_sizes,
    );
    let mut scheme = CommitmentSchemeVerifier::<MC>::new(format.config);
    scheme.commit(preprocessed_root, preprocessed_tree, &mut channel);
    scheme.commit(main_root, main_tree, &mut channel);
    channel.mix_felts(claim.public);
    if !channel.verify_pow_nonce(format.interaction_pow_bits, claim.interaction_pow) {
        return Err(Error::InteractionPow);
    }
    channel.mix_u64(claim.interaction_pow);
    let (relations, blind) = C::draw(&mut channel);
    channel.mix_felts(claim.claimed_sums);
    scheme.commit(interaction_root, interaction_tree, &mut channel);
    if let Some(public_sum) = claim.public_sum {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "QM31's addition is modular: it neither overflows nor panics"
        )]
        let total =
            claim.claimed_sums.iter().copied().sum::<SecureField>() + public_sum(&relations);
        if !total.is_zero() {
            return Err(Error::Logup);
        }
    }

    let set = layout
        .bind(&relations, &blind, claim.claimed_sums)
        .ok_or(Error::Shape("a claimed sum for each component"))?;
    let random_coeff = channel.draw_secure_felt();
    scheme.commit(composition_root, composition_tree, &mut channel);
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
    sample_points_from_zero(&mut points, layout, oods_point)
        .ok_or(Error::Shape("the component set's sample points"))?;
    if deep_values(&points) != format.deep_values {
        return Err(Error::Shape(
            "the sample points' DEEP values are not the format's",
        ));
    }
    let lifted: Vec<MaskedComponent<'_, dyn Component>> = set
        .iter()
        .map(|inner| MaskedComponent { inner: &**inner })
        .collect();
    let components = Components {
        components: lifted.iter().map(|c| c as &dyn Component).collect(),
        n_preprocessed_columns: preprocessed_tree.len(),
    };
    let composition = composition_oods_eval(&proof.sampled_values)
        .ok_or(Error::Shape("the composition's samples"))?;
    let air_level = air_log_size(layout).ok_or(Error::Shape("the AIR's level"))?;
    if composition
        != components.eval_composition_polynomial_at_point(
            oods_point,
            &proof.sampled_values,
            random_coeff,
            air_level,
        )
    {
        return Err(Error::Stark(VerificationError::OodsNotMatching));
    }
    Ok(Replayed {
        channel,
        scheme,
        points,
    })
}

/// Verifies `proof` of `claim` under `format` ([`replay`], then Stwo's
/// `verify_values`).
pub fn verify_masked<MC: MerkleChannel, C: MaskedComponents>(
    format: &MaskedFormat<'_>,
    claim: &Claim<'_, C::Relations, <MC::H as MerkleHasherLifted>::Hash>,
    layout: &C,
    proof: StarkProof<MC::H>,
) -> Result<(), Error> {
    let Replayed {
        mut channel,
        scheme,
        points,
    } = replay::<MC, C>(format, claim, layout, &proof)?;
    scheme
        .verify_values(points, proof.0, &mut channel)
        .map_err(Error::Stark)
}

/// The `format::MASKED_WRAP` proof in `bytes`: at most [`crate::MAX_PROOF_BYTES`], its
/// fixed layout read whole, its header `format::MASKED_WRAP`'s, every count its pin or
/// within its bound, nothing after it.
pub fn decode(bytes: &[u8]) -> Result<WrapProof, Error> {
    crate::layout::decode(bytes)
}

/// `proof`'s fixed layout: what the prover emits for `format::MASKED_WRAP`, and the one
/// encoding [`decode`] reads; `None` for a proof the layout cannot hold (a
/// column of other samples than [`samples`], a tree whose queried columns
/// differ in length), which no verifier would accept.
pub fn encode(proof: &WrapProof) -> Option<Vec<u8>> {
    crate::layout::encode(proof)
}

/// Verifies the `format::MASKED_WRAP` proof in `bytes` ([`decode`]) against the public
/// `words`.
pub fn verify_bytes(bytes: &[u8], words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    verify(decode(bytes)?, words)
}

/// Verifies a `format::MASKED_WRAP` proof of the wrap circuit against the public
/// `words`, and returns the statement they make: the program id and the
/// io-hash.
pub fn verify(proof: WrapProof, words: &[u32; PUBLIC_WORDS]) -> Result<Statement, Error> {
    verify_with(&MASKED_WRAP, &PREPROCESSED_ROOT_39, proof, words)
}

/// [`verify`] under `format`'s pins and the circuit `preprocessed_root`: a
/// verifier pinning other salts, `R` or widths refuses `format::MASKED_WRAP`'s proofs.
pub fn verify_with(
    format: &MaskedFormat<'_>,
    preprocessed_root: &[u8; 32],
    proof: WrapProof,
    words: &[u32; PUBLIC_WORDS],
) -> Result<Statement, Error> {
    let statement = Statement::from_words(words)?;
    if proof.format_version != format.number || proof.log_sizes[..] != *format.log_sizes {
        return Err(Error::Format);
    }
    let public: Vec<SecureField> = words.iter().map(|&word| embed(word)).collect();
    let public_sum = |relation: &GateRelation| {
        public_logup_sum(relation, LAYOUT.public_terms(public.iter().copied()))
    };
    let layout = WrapComponents::build(
        &GateRelation::dummy(),
        &BlindRelation::dummy(),
        &proof.log_sizes,
        &[SecureField::zero(); 3],
    );
    verify_masked::<Blake2bMerkleChannel, WrapComponents>(
        format,
        &Claim {
            log_sizes: &proof.log_sizes,
            circuit: Some(Blake2bHash(*preprocessed_root)),
            public: &public,
            public_sum: Some(&public_sum),
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

    use stwo::core::channel::Blake2bChannel;

    /// The wrap's set at `format::MASKED_WRAP`'s pins: the trees' widths 57 / 381 / 48 /
    /// 20 and 538 DEEP values, as pinned; the composition tree the last and
    /// at FRI's degree bound, the tallest; every column's samples
    /// [`samples`]'.
    #[test]
    fn the_pinned_shape_is_the_wrap_components() {
        let layout = WrapComponents::build(
            &GateRelation::dummy(),
            &BlindRelation::dummy(),
            &LOG_SIZES,
            &[SecureField::zero(); 3],
        );
        assert_eq!(shape_of(&layout, &PINS), Some((TREE_WIDTHS, DEEP_VALUES)));
        let trees = committed_log_sizes(&layout, &PINS).unwrap();
        assert_eq!(trees.iter().flatten().max(), Some(&LOG_DEGREE_BOUND));
        assert!(trees[3].iter().all(|&level| level == LOG_DEGREE_BOUND));
        let points = sample_points(&layout, CirclePoint::zero(), &PINS).unwrap();
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

    /// The header mixed for `format::MASKED_WRAP` is the segment transcript's
    /// (`mix_statement_header`), at its configuration and the wrap's log
    /// sizes; the constants are its registry entry.
    #[test]
    fn the_header_and_the_constants_are_format_39s() {
        let entry = &vos_pvm_proof::format::MASKED_WRAP;
        let masking = entry.masking.unwrap();
        assert_eq!(entry.number, FORMAT);
        assert_eq!(entry.pcs_config(), CONFIG);
        assert_eq!(entry.interaction_pow_bits(), INTERACTION_POW_BITS);
        assert_eq!(
            (
                masking.salt_columns,
                masking.fri_mask_columns,
                masking.log_mask_rows
            ),
            (PINS.salt_columns, PINS.fri_mask_columns, LOG_MASK_ROWS)
        );
        assert_eq!(entry.reference.sampled_values, DEEP_VALUES as u64);
        assert_eq!(entry.bytes, vos_pvm_proof::format::ProofBytes::FixedLayout);
        let mut ours = Blake2bChannel::default();
        mix_header(&mut ours, FORMAT, &CONFIG, &LOG_SIZES);
        let mut theirs = Blake2bChannel::default();
        vos_pvm_proof::proof::mix_statement_header(&mut theirs, FORMAT, &CONFIG, &LOG_SIZES);
        assert_eq!(ours.digest(), theirs.digest());
    }
}
