//! The masked verifier (masking variant (c), `proving.md` §5), over any
//! masked component set and Merkle channel ([`verify_masked`]): the masked
//! wrap's (`crate::masked`) and a device program's (`vos-pvm-device`).
//!
//! **The transcript:** the header (the format's number and configuration,
//! the log sizes); the program's words, if any; the preprocessed root
//! (columns at `n + 1`, unsalted); the main root (masked columns, blinding
//! columns, salts); the public values; the interaction PoW; the set's
//! relations, then the blinding relation; the blinded claimed sums; the
//! interaction root; the composition coefficient; the composition tree's
//! root (the whole composition, the FRI mask `R`, salts); the
//! out-of-domain point `z`; then Stwo's PCS
//! (`CommitmentSchemeVerifier::{commit, verify_values}`). Never
//! `stwo::core::verifier::verify`, whose composition split is hardcoded
//! (DIVERGENCE-004).
//!
//! **Everything is the format's** ([`MaskedFormat`]): the configuration
//! and its DEEP batching, the log sizes, the salts, `R` and `h`, the trees'
//! widths and the values the DEEP quotient batches. None is read from the
//! proof, whose own header is checked against them.
//!
//! **Before any Stwo call** (`check_shape`): the proof's log sizes and
//! configuration the format's (before the component set is built at them);
//! the set's trees the format's widths; four trees of commitments,
//! decommitments, sampled and queried values, each tree of the format's
//! width; every column's samples one for each of its sample points (the
//! composition tree's 4 coordinates and `R`'s columns one each, its salts
//! none); FRI's layers the rounds its degree bound folds in, its last layer
//! the format's; every M31 limb canonical.
//!
//! **What a format pins of a component set** ([`verifier_format`],
//! [`mask_rows`], [`reveals`]): pure functions of the format and the set's
//! layout. The masked prover sizes its masks by them, and the device
//! verifier fixes a program's floors and its pinned format with them, so
//! both read one definition, on the verify side.

use alloc::vec::Vec;

use num_traits::Zero;
use stwo::core::ColumnVec;
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::VerificationError;
use vos_pvm_recair_air::format::{Format, Masking, mix_statement_header};
use vos_pvm_recair_air::masking::{
    MaskedComponents, air_log_size, blinds_its_sums, committed_log_sizes, composition_oods_eval,
    eval_lifted_composition, sample_points, sample_points_from_zero,
};

use crate::{Error, secure_is_canonical, stark_is_canonical};

pub use vos_pvm_recair_air::masking::TREES;

/// A masked format, as its verifier pins it: nothing here is read from a
/// proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskedFormat<'a> {
    pub number: u32,
    /// Its configuration, its DEEP batching among it.
    pub config: PcsConfig,
    pub interaction_pow_bits: u32,
    /// Its salt and `R` columns, and `log2 h`, the prover's.
    pub masking: Masking,
    /// Each component's log size.
    pub log_sizes: &'a [u32],
    /// Each tree's columns.
    pub tree_widths: [usize; TREES],
    /// The values its DEEP quotient batches.
    pub deep_values: usize,
    /// The program the proof is of, as words the transcript mixes right
    /// after the header (a device program's chips, `crate`-independent);
    /// empty for a set whose shape the format alone fixes.
    pub program: &'a [u64],
}

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
    masking: &Masking,
) -> Option<([usize; TREES], usize)> {
    let points = sample_points(layout, CirclePoint::zero(), masking)?;
    let widths: [usize; TREES] = points
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    Some((widths, deep_values(&points)))
}

/// A masked registry entry as its verifier pins it
/// ([`MaskedFormat`]): its number, its
/// configuration and interaction PoW, its masking, `log_sizes`, and the
/// trees' widths and DEEP values of the component set laid out as `layout`
/// at them. `None` for an unmasked format or a set whose masks do not fit
/// its trees.
pub fn verifier_format<'a>(
    format: &Format,
    log_sizes: &'a [u32],
    layout: &impl MaskedComponents,
) -> Option<MaskedFormat<'a>> {
    let masking = format.masking?;
    let (tree_widths, deep_values) = shape_of(layout, &masking)?;
    Some(MaskedFormat {
        number: format.number,
        config: format.pcs_config(),
        interaction_pow_bits: format.interaction_pow_bits(),
        masking,
        log_sizes,
        tree_widths,
        deep_values,
        program: &[],
    })
}

/// Each component's `log2 h`: twice the rows a column of it reveals
/// ([`Reveal`]), rounded up to a power of two, capped at the format's `h`,
/// which must cover the rows themselves (`docs/design/proving.md` §5, how
/// large `h` must be); a cap below them leaves R1 refusing every
/// transcript. A component none of whose masked columns reads a
/// second row takes about half the `h` of one that does; R1 checks each on
/// every transcript. `None` for an unmasked format, or a set whose masks do
/// not fit its trees.
pub fn mask_rows(format: &Format, set: &impl MaskedComponents) -> Option<Vec<u32>> {
    let format_rows = format.masking?.log_mask_rows;
    reveals(format, set)?
        .into_iter()
        .map(|reveal| {
            if reveal.offsets == 0 {
                return Some(format_rows);
            }
            let rows = reveal.rows.checked_mul(2)?.checked_next_power_of_two()?;
            Some(rows.ilog2().min(format_rows))
        })
        .collect()
}

/// The most a component's masked column reveals of its randomizer in one
/// transcript (`docs/design/proving.md` §5's count): its widest set of
/// offsets `O` (0 when none of its masked columns is sampled) and
/// `4|O| + q(|O| + 1)` rows, four for each out-of-domain sample, one for
/// each of the `q` decommitted queries and one for each of the
/// composition's `|O|` reads at a query. Coinciding points reveal fewer;
/// R1 counts a transcript's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub offsets: usize,
    pub rows: usize,
}

/// [`Reveal`] for each of `set`'s components under `format`'s queries.
/// `None` for a set with no component, or a count that overflows.
pub fn reveals(format: &Format, set: &impl MaskedComponents) -> Option<Vec<Reveal>> {
    let queries = format.params.n_queries;
    let air_level = air_log_size(set)?;
    set.components()
        .into_iter()
        .map(|component| {
            let offsets = component
                .mask_points(CirclePoint::zero(), air_level)
                .iter()
                .skip(1)
                .flatten()
                .map(Vec::len)
                .max()
                .unwrap_or(0);
            let rows = offsets
                .checked_mul(4)?
                .checked_add(queries.checked_mul(offsets.checked_add(1)?)?)?;
            Some(Reveal { offsets, rows })
        })
        .collect()
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

/// Whether the claimed sums the public values fix are theirs under the
/// relations.
pub type BoundSums<'a, R> = dyn Fn(&R, &[SecureField]) -> bool + 'a;

/// What a masked proof claims beside its STARK proof.
pub struct Claim<'a, R, Hash> {
    /// Each component's log size, the proof's: the format's or refused.
    pub log_sizes: &'a [u32],
    /// The preprocessed root the circuit pins: the verifier's own, never
    /// the proof's.
    pub circuit: Hash,
    /// The values mixed after the main tree's root.
    pub public: &'a [SecureField],
    /// The public terms' logup sum under the relations, which the claimed
    /// sums must cancel (zero for a set with no public term).
    pub public_sum: &'a dyn Fn(&R) -> SecureField,
    /// Whether the claimed sums the public values fix
    /// ([`MaskedComponents::public_sums`]) are theirs under the relations;
    /// `None` for a set with none.
    pub bound_sums: Option<&'a BoundSums<'a, R>>,
    pub interaction_pow: u64,
    pub claimed_sums: &'a [SecureField],
}

/// A masked proof, without its format's header fields: what the masked
/// prover emits and [`verify_masked`] reads beside a [`Claim`].
#[derive(Clone, Debug)]
pub struct MaskedProof<H: MerkleHasherLifted> {
    pub interaction_pow: u64,
    /// Each component's claimed sum, blinded.
    pub claimed_sums: Vec<SecureField>,
    pub stark_proof: StarkProof<H>,
}

/// Each column of `values` holds one value for each of its sample points.
pub(crate) fn samples_fit<P, V>(
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
fn check_shape<H: MerkleHasherLifted>(
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
    pub points: Points,
}

/// The sample points, tree by tree.
type Points = TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>;

/// `claim`'s transcript under `format` replayed over `proof`, the component
/// set `C` laid out as `layout` (at the format's log sizes, any relations),
/// every check before Stwo's PCS done: the header, the shape
/// (`check_shape`), the circuit, the interaction PoW, the logup sums, the
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
    let (trees, mut points) = admitted(format, claim, layout, proof)?;
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

    let mut channel = MC::C::default();
    mix_statement_header(
        &mut channel,
        format.number,
        &format.config,
        format.log_sizes,
    );
    for &word in format.program {
        channel.mix_u64(word);
    }
    let mut scheme = CommitmentSchemeVerifier::<MC>::new(format.config);
    scheme.commit(preprocessed_root, preprocessed_tree, &mut channel);
    scheme.commit(main_root, main_tree, &mut channel);
    channel.mix_felts(claim.public);
    if !channel.verify_pow_nonce(format.interaction_pow_bits, claim.interaction_pow) {
        return Err(Error::InteractionPow);
    }
    channel.mix_u64(claim.interaction_pow);
    let (relations, blind) = C::draw(layout.active(), &mut channel);
    channel.mix_felts(claim.claimed_sums);
    scheme.commit(interaction_root, interaction_tree, &mut channel);
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "QM31's addition is modular: it neither overflows nor panics"
    )]
    let total =
        claim.claimed_sums.iter().copied().sum::<SecureField>() + (claim.public_sum)(&relations);
    if !total.is_zero() {
        return Err(Error::Logup);
    }
    if claim
        .bound_sums
        .is_some_and(|bound| !bound(&relations, claim.claimed_sums))
    {
        return Err(Error::Logup);
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
    let set: Vec<&dyn Component> = set.iter().map(|component| &**component).collect();
    check_composition(
        &set,
        layout,
        preprocessed_tree.len(),
        oods_point,
        random_coeff,
        &proof.sampled_values,
    )?;
    Ok(Replayed {
        channel,
        scheme,
        points,
    })
}

/// The checks on `proof` and `claim` before the transcript: the set blinds
/// its claimed sums (two blinded components at least, or none), the header
/// (the log sizes and the configuration the format's), the shape at `layout`'s
/// trees and sample points (`check_shape`), the claimed sums canonical and
/// the preprocessed root the circuit's. Returns the trees' column log sizes
/// and the sample points at zero.
fn admitted<H: MerkleHasherLifted, C: MaskedComponents>(
    format: &MaskedFormat<'_>,
    claim: &Claim<'_, C::Relations, H::Hash>,
    layout: &C,
    proof: &StarkProof<H>,
) -> Result<(TreeVec<Vec<u32>>, Points), Error> {
    if !blinds_its_sums(layout) {
        return Err(Error::Shape(
            "one blinded component: its claimed sum is in the clear",
        ));
    }
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
    let trees = committed_log_sizes(layout, &format.masking)
        .ok_or(Error::Shape("the component set's trees"))?;
    let points = sample_points(layout, CirclePoint::zero(), &format.masking)
        .ok_or(Error::Shape("the component set's sample points"))?;
    check_shape(format, &trees, &points, proof)?;
    if !claim.claimed_sums.iter().all(secure_is_canonical) {
        return Err(Error::Noncanonical);
    }
    if proof.commitments.first() != Some(&claim.circuit) {
        return Err(Error::Circuit);
    }
    Ok((trees, points))
}

/// The composition's coordinates, sampled at their point, against the
/// bound `set` lifted and evaluated at `oods_point` under `random_coeff`.
fn check_composition(
    set: &[&dyn Component],
    layout: &impl MaskedComponents,
    n_preprocessed_columns: usize,
    oods_point: CirclePoint<SecureField>,
    random_coeff: SecureField,
    sampled_values: &TreeVec<ColumnVec<Vec<SecureField>>>,
) -> Result<(), Error> {
    let composition =
        composition_oods_eval(sampled_values).ok_or(Error::Shape("the composition's samples"))?;
    let air_level = air_log_size(layout).ok_or(Error::Shape("the AIR's level"))?;
    if composition
        != eval_lifted_composition(
            set,
            n_preprocessed_columns,
            oods_point,
            sampled_values,
            random_coeff,
            air_level,
        )
    {
        return Err(Error::Stark(VerificationError::OodsNotMatching));
    }
    Ok(())
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

/// Whether `pow` meets `format`'s interaction PoW where [`replay`] checks
/// it: the header, the program's words, the first two of `commitments`
/// (the preprocessed and main roots) and `public` mixed, as there. A
/// pre-check over a proof's leading fields alone: what it refuses,
/// [`verify_masked`] refuses.
pub fn interaction_pow_holds<MC: MerkleChannel>(
    format: &MaskedFormat<'_>,
    public: &[SecureField],
    commitments: &[<MC::H as MerkleHasherLifted>::Hash],
    pow: u64,
) -> bool {
    let [preprocessed_root, main_root, ..] = commitments else {
        return false;
    };
    let mut channel = MC::C::default();
    mix_statement_header(
        &mut channel,
        format.number,
        &format.config,
        format.log_sizes,
    );
    for &word in format.program {
        channel.mix_u64(word);
    }
    MC::mix_root(&mut channel, *preprocessed_root);
    MC::mix_root(&mut channel, *main_root);
    channel.mix_felts(public);
    channel.verify_pow_nonce(format.interaction_pow_bits, pow)
}
