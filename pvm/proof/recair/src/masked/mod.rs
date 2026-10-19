//! The masked prover: masking variant (c) (`docs/design/proving.md` §5,
//! `research/slice-5/masking-review.md`), over any component set
//! ([`MaskedComponents`]) and any Merkle channel, in pin B's order
//! (`docs/design/slice-6-on-chain.md`):
//!
//! 1. the header, at the format's number and configuration, and the log
//!    sizes;
//! 2. the preprocessed tree: its columns extended one level, unmasked and
//!    unsalted;
//! 3. the main tree: each component's columns, then its blinding columns
//!    (one QM31 on its first row, the set's summing to zero: R2), every one
//!    masked `f + v_H·r` ([`MaskLayout`]), then the salts;
//! 4. the public values; the interaction PoW;
//! 5. the set's relations, then the blinding relation
//!    ([`MaskedComponents::draw`]);
//! 6. the blinded claimed sums; the interaction tree, masked and salted;
//! 7. the composition coefficient;
//! 8. the composition tree: the composition's 4 coordinates whole at its
//!    bound, never split, the FRI mask `R`'s uniform columns, the salts;
//! 9. the out-of-domain point `z`: the masks sampled at the AIR's level, the
//!    composition at `π(z)`, `R` at `z`, no salt sampled;
//! 10. Stwo's `prove_values`: the DEEP coefficients, FRI, the PoW, the
//!     queries.
//!
//! **The randomness** is hedged (R4, [`MaskRng`]). **R1** is checked on
//! every transcript: the randomizer's revealed functionals of full rank over
//! M31 ([`rank_m31`]); a deficient transcript is discarded and every mask
//! drawn again, at most [`MAX_ATTEMPTS`] times. Whether a transcript passes
//! is a function of public coins and the format, so the retry conditions on
//! a public event. **R3** holds by construction: `R`'s columns are the
//! format's (8 for format 39), whose independent DEEP coefficients span
//! QM31 over M31 but with probability about `p^-5`; no check.
//!
//! The format pins the masking ([`Masking`]); nothing here names the wrap,
//! whose set is [`WrapComponents`].

mod layout;
mod rank;
mod rng;
mod salts;

use std::time::{Duration, Instant};

use num_traits::{One, Zero};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use stwo::core::ColumnVec;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::PREPROCESSED_TRACE_IDX;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::{
    CommitmentSchemeProver, ComponentProver, ComponentProvers, DomainEvaluationAccumulator,
    ProvingError, Trace,
};
use stwo_constraint_framework::Relation;
use vos_pvm_final_verifier::masked::{MaskedFormat, shape_of};
use vos_pvm_proof::format::{Format, MASKED_WRAP, Masking};
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair_air::masked::{
    self as air, BLIND_COLUMNS, MASKED_COLUMN_EXPANSION, MASKED_LOG_CONSTRAINT_EXPANSION, MaskPins,
    MaskedComponent, MaskedComponents, WrapComponents,
};

pub use layout::MaskLayout;
pub use rank::rank_m31;
pub use rng::MaskRng;

use crate::prove::ProveError;
use crate::trace::{self, Evaluations, FirstRowFraction};

/// The attempts R1 may refuse before the prover gives up
/// ([`ProveError::MaskRank`]).
pub const MAX_ATTEMPTS: u32 = 8;

/// The trees' layout a masking pins.
pub const fn mask_pins(masking: &Masking) -> MaskPins {
    MaskPins {
        salt_columns: masking.salt_columns,
        fri_mask_columns: masking.fri_mask_columns,
    }
}

/// Format 39's trees: its salt and `R` columns, read from the registry.
pub const MASKED_WRAP_PINS: MaskPins = match &MASKED_WRAP.masking {
    Some(masking) => mask_pins(masking),
    None => panic!("format 39 pins its masking"),
};

/// A masked registry entry as its verifier pins it
/// (`vos_pvm_final_verifier::masked::MaskedFormat`): its number, its
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
    let pins = mask_pins(&masking);
    let (tree_widths, deep_values) = shape_of(layout, &pins)?;
    Some(MaskedFormat {
        number: format.number,
        config: format.pcs_config(),
        interaction_pow_bits: format.interaction_pow_bits(),
        pins,
        log_mask_rows: masking.log_mask_rows,
        log_sizes,
        tree_widths,
        deep_values,
    })
}

/// A component set's provers: what the masked prover evaluates the
/// composition with, beside [`MaskedComponents`]' verifier-side view.
pub trait MaskedProvers: MaskedComponents {
    /// The components in commitment order, their bounds at their rows'
    /// level, as [`MaskedComponents::components`].
    fn provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>>;
}

impl MaskedProvers for WrapComponents {
    fn provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![&self.p2, &self.qm31, &self.h8]
    }
}

/// A component prover whose columns are committed one level up
/// ([`MaskedComponent`]); it evaluates its constraints on the committed
/// evaluations as they are.
struct Lifted<'a>(MaskedComponent<'a, dyn ComponentProver<SimdBackend> + 'a>);

impl Component for Lifted<'_> {
    fn n_constraints(&self) -> usize {
        self.0.n_constraints()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.0.max_constraint_log_degree_bound()
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        self.0.trace_log_degree_bounds()
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        max_log_degree_bound: u32,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        self.0.mask_points(point, max_log_degree_bound)
    }

    fn preprocessed_column_indices(&self) -> ColumnVec<usize> {
        self.0.preprocessed_column_indices()
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) {
        self.0.evaluate_constraint_quotients_at_point(
            point,
            mask,
            evaluation_accumulator,
            max_log_degree_bound,
        )
    }
}

impl ComponentProver<SimdBackend> for Lifted<'_> {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, SimdBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<SimdBackend>,
    ) {
        self.0
            .inner
            .evaluate_constraint_quotients_on_domain(trace, evaluation_accumulator)
    }
}

/// A component set's interaction trace under its relations: each
/// component's columns and claimed sum, its fractions in pairs with its
/// blinding's fraction after its own.
pub type Interaction<'a, R> =
    dyn Fn(&R, &[FirstRowFraction]) -> Vec<(Evaluations, SecureField)> + 'a;

/// What the masked prover proves: a component set's columns, unmasked, at
/// their rows' level.
pub struct MaskedTrace<'a, R> {
    /// Each component's log size, in commitment order.
    pub log_sizes: &'a [u32],
    /// The preprocessed columns, in commitment order.
    pub preprocessed: Evaluations,
    /// Each component's main columns, without its blinding columns.
    pub main: Vec<Evaluations>,
    /// The values mixed after the main tree's root.
    pub public: &'a [SecureField],
    /// The interaction trace.
    pub interaction: &'a Interaction<'a, R>,
}

/// A masked proof, without its format's header fields.
#[derive(Clone, Debug)]
pub struct MaskedProof<H: MerkleHasherLifted> {
    pub interaction_pow: u64,
    /// Each component's claimed sum, blinded.
    pub claimed_sums: Vec<SecureField>,
    pub stark_proof: StarkProof<H>,
}

/// What a masked prove measured.
#[derive(Clone, Copy, Debug, Default)]
pub struct MaskStats {
    /// The attempts made, the last accepted.
    pub attempts: u32,
    /// R1 on the accepted attempt.
    pub rank_check: Duration,
    /// The most functionals one column class revealed, against `h`.
    pub revealed_rows: usize,
}

/// Proves `trace` masked under `format`, a masked format that pins its
/// masking, as the component set `C` on `MC`'s trees and channel, its
/// randomness from `rng` hedged with the statement's and the main columns'
/// digest.
///
/// The claimed sums are blinded (R2) by values summing to zero, so their
/// total is the unblinded one. A set of one component is therefore left
/// unblinded: its claimed sum is in the clear, and its verifier must check
/// it against a public total (`claimed + public = 0`), which makes it
/// public; a verifier that checks no total would leave a witness-dependent
/// value in the clear.
pub fn prove_masked<MC: MerkleChannel, C: MaskedProvers>(
    format: &Format,
    trace: MaskedTrace<'_, C::Relations>,
    rng: MaskRng,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let masking = match format.masking {
        Some(masking) if format.masked => masking,
        _ => return Err(ProveError::UnmaskedFormat),
    };
    if trace.main.len() != trace.log_sizes.len() || trace.log_sizes.is_empty() {
        return Err(ProveError::TraceShape(
            "one main trace per component expected",
        ));
    }
    let composition = trace
        .log_sizes
        .iter()
        .max()
        .and_then(|log_size| log_size.checked_add(MASKED_LOG_CONSTRAINT_EXPANSION))
        .ok_or(ProveError::TraceShape("a component's log size overflows"))?;
    let lifting = composition + format.params.log_blowup;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let witness = rng::witness_digest(
        &rng::Statement {
            format,
            masking: &masking,
            log_sizes: trace.log_sizes,
            channel: core::any::type_name::<MC>(),
            public: trace.public,
        },
        &trace.main,
    );
    let layouts = layout::layouts(trace.log_sizes, masking.log_mask_rows)?;
    let preprocessed: Vec<CircleCoefficients<SimdBackend>> =
        SimdBackend::interpolate_columns(trace.preprocessed, &twiddles)
            .into_iter()
            .map(|poly| poly.extend(poly.log_size() + MASKED_COLUMN_EXPANSION))
            .collect();
    let mut main = Vec::with_capacity(trace.main.len());
    for (columns, &log_size) in trace.main.into_iter().zip(trace.log_sizes) {
        if columns
            .iter()
            .any(|column| column.domain.log_size() != log_size)
        {
            return Err(ProveError::TraceShape(
                "a main column of another size than its component",
            ));
        }
        main.push(SimdBackend::interpolate_columns(columns, &twiddles));
    }
    let setup = Setup {
        format,
        masking,
        composition,
        lifting,
        twiddles: &twiddles,
        layouts: &layouts,
        log_sizes: trace.log_sizes,
        public: trace.public,
        interaction: trace.interaction,
    };
    for attempt in 0..MAX_ATTEMPTS {
        let mut stream = rng.attempt(&witness, attempt)?;
        if let Some((proof, mut stats)) =
            prove_once::<MC, C>(&setup, &preprocessed, &main, &mut stream)?
        {
            stats.attempts = attempt + 1;
            return Ok((proof, stats));
        }
    }
    Err(ProveError::MaskRank)
}

/// What every attempt shares.
struct Setup<'a, R> {
    format: &'a Format,
    masking: Masking,
    composition: u32,
    lifting: u32,
    twiddles: &'a TwiddleTree<SimdBackend>,
    layouts: &'a [MaskLayout],
    log_sizes: &'a [u32],
    public: &'a [SecureField],
    interaction: &'a Interaction<'a, R>,
}

/// An attempt's proof and what it measured, `None` when R1 refuses its
/// transcript.
type Attempt<H> = Option<(MaskedProof<H>, MaskStats)>;

/// One attempt from `rng`'s stream.
fn prove_once<MC: MerkleChannel, C: MaskedProvers>(
    setup: &Setup<'_, C::Relations>,
    preprocessed: &[CircleCoefficients<SimdBackend>],
    main: &[Vec<CircleCoefficients<SimdBackend>>],
    rng: &mut ChaCha20Rng,
) -> Result<Attempt<MC::H>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let Setup {
        format,
        masking,
        composition,
        lifting,
        twiddles,
        layouts,
        log_sizes,
        public,
        interaction,
    } = *setup;
    let pins = mask_pins(&masking);
    let config = format.pcs_config();
    let channel = &mut MC::C::default();
    mix_statement_header(channel, format.number, &config, log_sizes);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut builder = scheme.tree_builder();
    builder.extend_polys(preprocessed.to_vec());
    builder.commit(channel);

    let blinding = blinding(log_sizes.len(), rng);
    let blinding_columns: Vec<Vec<CircleCoefficients<SimdBackend>>> = blinding
        .iter()
        .zip(log_sizes)
        .map(|(&value, &log_size)| blinding_polys(value, log_size, twiddles))
        .collect();
    let columns: Vec<&CircleCoefficients<SimdBackend>> = main
        .iter()
        .zip(&blinding_columns)
        .flat_map(|(own, blinding)| own.iter().chain(blinding))
        .collect();
    let masked = layout::mask_columns(&columns, layouts, rng)?;
    drop(blinding_columns);
    salts::commit_salted(
        &mut scheme,
        masked,
        lifting,
        masking.salt_columns,
        rng,
        channel,
    );

    channel.mix_felts(public);
    let interaction_pow = <SimdBackend as stwo::core::proof_of_work::GrindOps<MC::C>>::grind(
        channel,
        format.interaction_pow_bits(),
    );
    channel.mix_u64(interaction_pow);
    let (relations, blind) = C::draw(channel);

    let denominator: SecureField =
        Relation::<BaseField, SecureField>::combine(&blind, &[BaseField::one()]);
    let fractions: Vec<FirstRowFraction> = blinding
        .iter()
        .map(|&numerator| FirstRowFraction {
            numerator,
            denominator,
        })
        .collect();
    let interaction_columns = interaction(&relations, &fractions);
    if interaction_columns.len() != log_sizes.len() {
        return Err(ProveError::TraceShape(
            "one interaction trace per component expected",
        ));
    }
    let claimed_sums: Vec<SecureField> = interaction_columns.iter().map(|(_, sum)| *sum).collect();
    let polys = SimdBackend::interpolate_columns(
        interaction_columns
            .into_iter()
            .flat_map(|(columns, _)| columns)
            .collect(),
        twiddles,
    );
    let masked = layout::mask_columns(&polys.iter().collect::<Vec<_>>(), layouts, rng)?;
    drop(polys);
    channel.mix_felts(&claimed_sums);
    salts::commit_salted(
        &mut scheme,
        masked,
        lifting,
        masking.salt_columns,
        rng,
        channel,
    );

    let set = C::new(&relations, &blind, log_sizes, &claimed_sums).ok_or(
        ProveError::TraceShape("the component set refuses its log sizes or claimed sums"),
    )?;
    if air::composition_log_degree_bound(&set) != Some(composition) {
        return Err(ProveError::Masking(
            "the set's composition bound is not its tallest log size plus 2",
        ));
    }
    let air_level =
        air::air_log_size(&set).ok_or(ProveError::Masking("the set has no AIR level"))?;
    let lifted: Vec<Lifted<'_>> = set
        .provers()
        .into_iter()
        .map(|inner| Lifted(MaskedComponent { inner }))
        .collect();
    let provers = ComponentProvers {
        components: lifted
            .iter()
            .map(|component| component as &dyn ComponentProver<SimdBackend>)
            .collect(),
        n_preprocessed_columns: scheme.trees[PREPROCESSED_TRACE_IDX].polynomials.len(),
    };

    let random_coeff = channel.draw_secure_felt();
    let composition_poly = provers.compute_composition_polynomial(
        random_coeff,
        &scheme.trace(),
        twiddles,
        format.params.log_blowup,
    );
    if composition_poly.log_size() != composition {
        return Err(ProveError::Masking(
            "the composition polynomial is not at its bound",
        ));
    }
    let mut polys = composition_poly.into_coordinate_polys().to_vec();
    let seeds: Vec<[u8; 32]> = (0..masking.fri_mask_columns).map(|_| rng.r#gen()).collect();
    polys.extend(
        seeds
            .into_iter()
            .map(|seed| salts::uniform_poly(seed, composition)),
    );
    salts::commit_salted(
        &mut scheme,
        polys,
        lifting,
        masking.salt_columns,
        rng,
        channel,
    );

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let points = air::sample_points(&set, oods_point, &pins).ok_or(ProveError::Masking(
        "the set's mask points do not fit its trees",
    ))?;
    let fits = points.len() == scheme.trees.len()
        && points
            .iter()
            .zip(scheme.trees.iter())
            .all(|(columns, tree)| columns.len() == tree.polynomials.len());
    let salts_unsampled = points.iter().skip(1).all(|columns| {
        columns
            .len()
            .checked_sub(masking.salt_columns)
            .is_some_and(|start| columns[start..].iter().all(Vec::is_empty))
    });
    if !fits || !salts_unsampled {
        return Err(ProveError::Masking(
            "the sample points do not fit the trees, or a salt is sampled",
        ));
    }
    let extended = scheme.prove_values(points.clone(), channel);
    let stark_proof = StarkProof(extended.proof);

    let components = Components {
        components: lifted.iter().map(|c| c as &dyn Component).collect(),
        n_preprocessed_columns: provers.n_preprocessed_columns,
    };
    let composition_value = air::composition_oods_eval(&stark_proof.sampled_values).ok_or(
        ProveError::Masking("the composition's coordinates are not sampled once each"),
    )?;
    if composition_value
        != components.eval_composition_polynomial_at_point(
            oods_point,
            &stark_proof.sampled_values,
            random_coeff,
            air_level,
        )
    {
        return Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied));
    }

    let started = Instant::now();
    let revealed = rank::revealed_functionals(
        &components,
        &points,
        oods_point,
        &extended.aux.unsorted_query_locations,
        lifting,
        masking.log_mask_rows,
    )
    .ok_or(ProveError::Masking(
        "R1's column classes do not fit the sample points",
    ))?;
    let stats = MaskStats {
        attempts: 0,
        rank_check: started.elapsed(),
        revealed_rows: revealed.rows,
    };
    if !revealed.independent {
        return Ok(None);
    }
    Ok(Some((
        MaskedProof {
            interaction_pow,
            claimed_sums,
            stark_proof,
        },
        stats,
    )))
}

/// The blinding values (R2), one a component: uniform but the last, which
/// makes them sum to zero, so the claimed sums' total is the unblinded one.
/// A set of one component is left unblinded.
fn blinding(n_components: usize, rng: &mut ChaCha20Rng) -> Vec<SecureField> {
    let mut values: Vec<SecureField> = (1..n_components)
        .map(|_| SecureField::from_m31_array(core::array::from_fn(|_| rng.r#gen())))
        .collect();
    values.push(-values.iter().copied().sum::<SecureField>());
    values
}

/// A component's blinding columns: `value`'s limbs on the coset's first row,
/// zero on every other.
fn blinding_polys(
    value: SecureField,
    log_size: u32,
    twiddles: &TwiddleTree<SimdBackend>,
) -> Vec<CircleCoefficients<SimdBackend>> {
    let columns: Vec<Vec<BaseField>> = value
        .to_m31_array()
        .into_iter()
        .map(|limb| {
            let mut column = vec![BaseField::zero(); 1 << log_size];
            column[0] = limb;
            column
        })
        .collect();
    SimdBackend::interpolate_columns(trace::evaluations(&columns, log_size), twiddles)
}

const _: () = assert!(BLIND_COLUMNS == SECURE_EXTENSION_DEGREE);
