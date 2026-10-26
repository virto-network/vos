//! The masked prover: masking variant (c) (`docs/design/proving.md` §5,
//! R1–R8), over any component set ([`MaskedComponents`]) and any Merkle
//! channel, in the masked transcript's order
//! (`vos_pvm_final_verifier::masked`):
//!
//! 1. the header, at the format's number and configuration, and the log
//!    sizes;
//! 2. the preprocessed tree: its columns extended one level, unmasked and
//!    unsalted;
//! 3. the main tree: each component's columns, then its blinding columns
//!    (one QM31 on its first row, the set's summing to zero: R2), every one
//!    masked `f + v_H·r` (`layout::MaskLayout`), then the salts;
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
//! every transcript: the randomizer's revealed functionals of full rank
//! over M31 (`rank::rank_m31`); a deficient transcript is discarded and every
//! mask drawn again, at most [`MAX_ATTEMPTS`] times. Whether a transcript
//! passes is a function of public coins and the format, so the retry
//! conditions on a public event. **R3** holds by construction: `R`'s
//! columns are the format's (8 for `format::MASKED_WRAP`), whose
//! independent DEEP coefficients span QM31 over M31 but with probability
//! about `p^-5`; no check.
//!
//! The format pins the masking ([`Masking`]); nothing here names the wrap,
//! whose set is [`WrapComponents`].

pub mod device;
mod drawn;
mod layout;
mod rank;
mod rng;
mod salts;
pub mod segment;

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
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::{BackendForChannel, Column};
use stwo::prover::poly::circle::{CircleCoefficients, CircleEvaluation, PolyOps};
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::{
    CommitmentSchemeProver, ComponentProver, ComponentProvers, DomainEvaluationAccumulator,
    ProvingError, Trace,
};
use stwo_constraint_framework::Relation;
use vos_pvm_final_verifier::masked::{MaskedFormat, shape_of};
use vos_pvm_proof::format::{Format, Masking};
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair_air::masked::{
    self as air, BLIND_COLUMNS, BlindRelation, MASKED_COLUMN_EXPANSION,
    MASKED_LOG_CONSTRAINT_EXPANSION, MaskPins, MaskedComponent, MaskedComponents, WrapComponents,
};

pub use drawn::{Drawn, drawn_in};
use layout::MaskLayout;
#[cfg(feature = "seeded-masks")]
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

/// The masked lifting height of components of `log_sizes` under
/// `format`'s blowup: the tallest, raised by the masked constraint
/// expansion. `None` for no components, or a height that overflows.
pub(crate) fn lifting_log_size(format: &Format, log_sizes: &[u32]) -> Option<u32> {
    log_sizes
        .iter()
        .max()?
        .checked_add(MASKED_LOG_CONSTRAINT_EXPANSION)?
        .checked_add(format.params.log_blowup)
}

/// Each component's `log2 h`: twice the rows a column of it reveals,
/// `4|O| + q(|O| + 1)` for its widest set of offsets `O` and the format's `q`
/// queries (`docs/design/proving.md` §8), rounded up to a power of two, at
/// most the format's `h`. A component none of whose masked columns reads a
/// second row takes about half the `h` of one that does; R1 checks each on
/// every transcript. `None` for an unmasked format, or a set whose masks do
/// not fit its trees.
pub fn mask_rows(format: &Format, set: &impl MaskedComponents) -> Option<Vec<u32>> {
    let format_rows = format.masking?.log_mask_rows;
    let queries = format.params.n_queries;
    let air_level = air::air_log_size(set)?;
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
            if offsets == 0 {
                return Some(format_rows);
            }
            let revealed = offsets
                .checked_mul(4)?
                .checked_add(queries.checked_mul(offsets.checked_add(1)?)?)?;
            let rows = revealed.checked_mul(2)?.checked_next_power_of_two()?;
            Some(rows.ilog2().min(format_rows))
        })
        .collect()
}

/// The preprocessed columns as a masked format commits them: interpolated
/// on `twiddles` and each extended one level.
pub(crate) fn extend_preprocessed(
    preprocessed: Evaluations,
    twiddles: &TwiddleTree<SimdBackend>,
) -> Vec<CircleCoefficients<SimdBackend>> {
    SimdBackend::interpolate_columns(preprocessed, twiddles)
        .into_iter()
        .map(|poly| poly.extend(poly.log_size() + MASKED_COLUMN_EXPANSION))
        .collect()
}

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
        program: &[],
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

/// Component `c`'s main columns, without its blinding columns, in Stwo's
/// storage order: borrowed, the prover interpolating them a component at a
/// time, so it keeps no copy of the trace.
pub type MainColumns<'a> = dyn Fn(usize) -> Vec<&'a BaseColumn> + Sync + 'a;

/// What the masked prover proves: a component set's columns, unmasked, at
/// their rows' level.
pub struct MaskedTrace<'a, R, A = ()> {
    /// The components the set holds ([`MaskedComponents::Active`]).
    pub active: A,
    /// Each component's log size, in commitment order.
    pub log_sizes: &'a [u32],
    /// The preprocessed columns, in commitment order.
    pub preprocessed: Evaluations,
    /// Each component's main columns ([`MainColumns`]).
    pub main: &'a MainColumns<'a>,
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
    /// The column classes R1 checked: every masked column's level, its
    /// quotient's lift and its offsets, each once.
    pub classes: usize,
    /// The most functionals one column class revealed, against `h`.
    pub revealed_rows: usize,
}

/// Proves `trace` masked under `format`, a masked format that pins its
/// masking, as the component set `C` on `MC`'s trees and channel, its
/// randomness from `rng` hedged with the statement's and the main columns'
/// digest.
///
/// The claimed sums are blinded (R2) by values summing to zero, so their
/// total is the unblinded one; the sums the public values fix
/// ([`MaskedComponents::public_sums`]) are left unblinded. A set of one
/// blinded component is therefore left unblinded: its claimed sum is in the
/// clear, and its verifier must check it against a public total
/// (`claimed + public = 0`), which makes it public; a verifier that checks no
/// total would leave a witness-dependent value in the clear.
///
/// Each component's mask takes its own `h` ([`mask_rows`]).
pub fn prove_masked<MC: MerkleChannel, C: MaskedProvers>(
    format: &Format,
    trace: MaskedTrace<'_, C::Relations, C::Active>,
    rng: MaskRng,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_masked_checked::<MC, C>(format, trace, rng, Checks::ALL)
}

/// [`prove_masked`] without the prover's out-of-domain check of the
/// constraints: a witness that breaks one is proved all the same, so the
/// soundness tests can hand the verifier a forced proof. Only the prover's
/// tests have it, on the dev edge that gives them [`MaskRng::Seeded`]
/// (`seeded-masks`); no production build does.
#[cfg(feature = "seeded-masks")]
pub fn prove_masked_unchecked<MC: MerkleChannel, C: MaskedProvers>(
    format: &Format,
    trace: MaskedTrace<'_, C::Relations, C::Active>,
    rng: MaskRng,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_masked_checked::<MC, C>(
        format,
        trace,
        rng,
        Checks {
            constraints: false,
            ..Checks::ALL
        },
    )
}

/// What the prover holds itself to: the honest prover all of it; a forced
/// proof, on the tests' dev edge, without one.
#[derive(Clone, Copy, Debug)]
pub struct Checks {
    /// The out-of-domain check of the constraints.
    pub constraints: bool,
    /// The public sums ([`MaskedComponents::public_sums`]) left unblinded.
    pub public_unblinded: bool,
}

impl Checks {
    pub const ALL: Self = Self {
        constraints: true,
        public_unblinded: true,
    };
}

/// [`prove_masked`], held to `checks`.
pub(crate) fn prove_masked_checked<MC: MerkleChannel, C: MaskedProvers>(
    format: &Format,
    trace: MaskedTrace<'_, C::Relations, C::Active>,
    rng: MaskRng,
    checks: Checks,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_masked_program::<MC, C>(format, &[], trace, rng, checks)
}

/// [`prove_masked_checked`] of `program`, words the transcript mixes right
/// after the header (`MaskedFormat::program`).
pub(crate) fn prove_masked_program<MC: MerkleChannel, C: MaskedProvers>(
    format: &Format,
    program: &[u64],
    trace: MaskedTrace<'_, C::Relations, C::Active>,
    rng: MaskRng,
    checks: Checks,
) -> Result<(MaskedProof<MC::H>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let masking = match format.masking {
        Some(masking) if format.masked => masking,
        _ => return Err(ProveError::UnmaskedFormat),
    };
    if trace.log_sizes.is_empty() {
        return Err(ProveError::TraceShape("no component"));
    }
    for (component, &log_size) in trace.log_sizes.iter().enumerate() {
        if (trace.main)(component)
            .iter()
            .any(|column| column.len() != 1usize.checked_shl(log_size).unwrap_or(0))
        {
            return Err(ProveError::TraceShape(
                "a main column of another size than its component",
            ));
        }
    }
    let lifting = lifting_log_size(format, trace.log_sizes)
        .ok_or(ProveError::TraceShape("a component's log size overflows"))?;
    let composition = lifting - format.params.log_blowup;
    let twiddles =
        SimdBackend::precompute_twiddles(CanonicCoset::new(lifting).circle_domain().half_coset);
    let witness = rng::witness_digest(
        &rng::Statement {
            format,
            masking: &masking,
            log_sizes: trace.log_sizes,
            public: trace.public,
        },
        trace.main,
    );
    drawn::note("the witness digest", &witness);
    let set_layout = C::layout(trace.active, trace.log_sizes).ok_or(ProveError::TraceShape(
        "the component set refuses its log sizes",
    ))?;
    let mask_rows = mask_rows(format, &set_layout)
        .ok_or(ProveError::Masking("the set's masks do not fit its trees"))?;
    let public_sums = if checks.public_unblinded {
        set_layout.public_sums()
    } else {
        Vec::new()
    };
    drop(set_layout);
    let classes: Vec<(u32, u32)> = trace
        .log_sizes
        .iter()
        .copied()
        .zip(mask_rows.iter().copied())
        .collect();
    let layouts = layout::layouts(&classes)?;
    let preprocessed = extend_preprocessed(trace.preprocessed, &twiddles);
    let setup = Setup {
        format,
        program,
        masking,
        active: trace.active,
        mask_rows: &mask_rows,
        public_sums: &public_sums,
        composition,
        lifting,
        twiddles: &twiddles,
        layouts: &layouts,
        log_sizes: trace.log_sizes,
        public: trace.public,
        main: trace.main,
        interaction: trace.interaction,
        check_constraints: checks.constraints,
    };
    for attempt in 0..MAX_ATTEMPTS {
        let mut stream = rng.attempt(&witness, attempt)?;
        if let Some((proof, r1)) = prove_once::<MC, C>(&setup, &preprocessed, &mut stream)? {
            let stats = MaskStats {
                attempts: attempt + 1,
                rank_check: r1.took,
                classes: r1.classes,
                revealed_rows: r1.rows,
            };
            return Ok((proof, stats));
        }
    }
    Err(ProveError::MaskRank)
}

/// What every attempt shares.
struct Setup<'a, 'm, R, A> {
    format: &'a Format,
    /// The words mixed after the header.
    program: &'a [u64],
    masking: Masking,
    active: A,
    /// Each component's `log2 h`.
    mask_rows: &'a [u32],
    /// The components left unblinded.
    public_sums: &'a [usize],
    composition: u32,
    lifting: u32,
    twiddles: &'a TwiddleTree<SimdBackend>,
    layouts: &'a [std::sync::Arc<MaskLayout>],
    log_sizes: &'a [u32],
    public: &'a [SecureField],
    main: &'m MainColumns<'m>,
    interaction: &'a Interaction<'a, R>,
    check_constraints: bool,
}

/// A commitment scheme on `MC`'s trees.
type Scheme<'a, MC> = CommitmentSchemeProver<'a, SimdBackend, MC>;

/// The sample points, one list a column, one tree a list.
type Points = TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>;

/// What R1 measured on a transcript it accepted.
struct R1 {
    took: Duration,
    classes: usize,
    rows: usize,
}

/// An attempt's proof and what R1 measured, `None` when R1 refuses its
/// transcript.
type Attempt<H> = Option<(MaskedProof<H>, R1)>;

/// One attempt from `rng`'s stream.
fn prove_once<MC: MerkleChannel, C: MaskedProvers>(
    setup: &Setup<'_, '_, C::Relations, C::Active>,
    preprocessed: &[CircleCoefficients<SimdBackend>],
    rng: &mut ChaCha20Rng,
) -> Result<Attempt<MC::H>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let format = setup.format;
    let config = format.pcs_config();
    let channel = &mut MC::C::default();
    mix_statement_header(channel, format.number, &config, setup.log_sizes);
    for &word in setup.program {
        channel.mix_u64(word);
    }
    let mut scheme = Scheme::<MC>::new(config, setup.twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut builder = scheme.tree_builder();
    builder.extend_polys(preprocessed.to_vec());
    builder.commit(channel);

    let blinding = commit_main(setup, &mut scheme, rng, channel)?;

    channel.mix_felts(setup.public);
    let interaction_pow = <SimdBackend as stwo::core::proof_of_work::GrindOps<MC::C>>::grind(
        channel,
        format.interaction_pow_bits(),
    );
    channel.mix_u64(interaction_pow);
    let (relations, blind) = C::draw(setup.active, channel);

    let claimed_sums = commit_interaction(
        setup,
        &mut scheme,
        (&relations, &blind),
        &blinding,
        rng,
        channel,
    )?;

    let (set, air_level) = masked_set::<C>(setup, &relations, &blind, &claimed_sums)?;
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

    let random_coeff = commit_composition(setup, &mut scheme, &provers, rng, channel)?;

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let points = checked_points(setup, &set, &scheme, oods_point)?;
    let extended = scheme.prove_values(points.clone(), channel);
    let stark_proof = StarkProof(extended.proof);

    let components = Components {
        components: lifted.iter().map(|c| c as &dyn Component).collect(),
        n_preprocessed_columns: provers.n_preprocessed_columns,
    };
    let composition_value = air::composition_oods_eval(&stark_proof.sampled_values).ok_or(
        ProveError::Masking("the composition's coordinates are not sampled once each"),
    )?;
    if setup.check_constraints
        && composition_value
            != components.eval_composition_polynomial_at_point(
                oods_point,
                &stark_proof.sampled_values,
                random_coeff,
                air_level,
            )
    {
        return Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied));
    }

    let Some(r1) = rank_check(
        setup,
        &components,
        &points,
        oods_point,
        &extended.aux.unsorted_query_locations,
    )?
    else {
        return Ok(None);
    };
    Ok(Some((
        MaskedProof {
            interaction_pow,
            claimed_sums,
            stark_proof,
        },
        r1,
    )))
}

/// The main tree: each component's columns, then its blinding columns, all
/// masked, then the salts. Returns the blinding values. A component's
/// columns are interpolated from the borrowed trace, masked and their
/// coefficients dropped before the next's; the masks' seeds are drawn for
/// every column first, in order.
fn commit_main<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<Vec<SecureField>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let blinding = blinding(setup.log_sizes.len(), setup.public_sums, rng);
    let widths: Vec<usize> = (0..setup.log_sizes.len())
        .map(|component| (setup.main)(component).len() + BLIND_COLUMNS)
        .collect();
    let mut seeds = layout::seeds(widths.iter().sum(), rng).into_iter();
    let mut masked = Vec::with_capacity(widths.iter().sum());
    for (component, ((&value, &log_size), &log_mask_rows)) in blinding
        .iter()
        .zip(setup.log_sizes)
        .zip(setup.mask_rows)
        .enumerate()
    {
        let domain = CanonicCoset::new(log_size).circle_domain();
        let own = SimdBackend::interpolate_columns(
            (setup.main)(component)
                .into_iter()
                .map(|column| CircleEvaluation::new(domain, column.clone()))
                .collect(),
            setup.twiddles,
        );
        let blinding = blinding_polys(value, log_size, setup.twiddles);
        let columns: Vec<(&CircleCoefficients<SimdBackend>, u32)> = own
            .iter()
            .chain(&blinding)
            .map(|column| (column, log_mask_rows))
            .collect();
        let seeds: Vec<[u8; 32]> = seeds.by_ref().take(columns.len()).collect();
        masked.extend(layout::mask_with(&columns, seeds, setup.layouts)?);
    }
    salts::commit_salted(
        scheme,
        masked,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(blinding)
}

/// The interaction tree under the drawn `(relations, blind)`: the blinded
/// claimed sums mixed, then the columns masked and salted. Returns the
/// blinded claimed sums.
fn commit_interaction<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    (relations, blind): (&R, &BlindRelation),
    blinding: &[SecureField],
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<Vec<SecureField>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let denominator: SecureField =
        Relation::<BaseField, SecureField>::combine(blind, &[BaseField::one()]);
    let fractions: Vec<FirstRowFraction> = blinding
        .iter()
        .map(|&numerator| FirstRowFraction {
            numerator,
            denominator,
        })
        .collect();
    let interaction_columns = (setup.interaction)(relations, &fractions);
    if interaction_columns.len() != setup.log_sizes.len() {
        return Err(ProveError::TraceShape(
            "one interaction trace per component expected",
        ));
    }
    let claimed_sums: Vec<SecureField> = interaction_columns.iter().map(|(_, sum)| *sum).collect();
    let column_rows: Vec<u32> = interaction_columns
        .iter()
        .zip(setup.mask_rows)
        .flat_map(|((columns, _), &log_mask_rows)| {
            core::iter::repeat_n(log_mask_rows, columns.len())
        })
        .collect();
    let polys = SimdBackend::interpolate_columns(
        interaction_columns
            .into_iter()
            .flat_map(|(columns, _)| columns)
            .collect(),
        setup.twiddles,
    );
    let columns: Vec<(&CircleCoefficients<SimdBackend>, u32)> =
        polys.iter().zip(column_rows).collect();
    let masked = layout::mask_columns(&columns, setup.layouts, rng)?;
    drop(polys);
    channel.mix_felts(&claimed_sums);
    salts::commit_salted(
        scheme,
        masked,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(claimed_sums)
}

/// The component set at the drawn relations and the blinded claimed sums,
/// its composition at the setup's bound, and its AIR level.
fn masked_set<C: MaskedProvers>(
    setup: &Setup<'_, '_, C::Relations, C::Active>,
    relations: &C::Relations,
    blind: &BlindRelation,
    claimed_sums: &[SecureField],
) -> Result<(C, u32), ProveError> {
    let set = C::new(
        setup.active,
        relations,
        blind,
        setup.log_sizes,
        claimed_sums,
    )
    .ok_or(ProveError::TraceShape(
        "the component set refuses its log sizes or claimed sums",
    ))?;
    if air::composition_log_degree_bound(&set) != Some(setup.composition) {
        return Err(ProveError::Masking(
            "the set's composition bound is not its tallest log size plus 2",
        ));
    }
    let air_level =
        air::air_log_size(&set).ok_or(ProveError::Masking("the set has no AIR level"))?;
    Ok((set, air_level))
}

/// The composition tree: the composition's 4 coordinates whole at its
/// bound, the FRI mask `R`'s uniform columns, the salts. Returns the
/// composition coefficient drawn before it.
fn commit_composition<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    scheme: &mut Scheme<'_, MC>,
    provers: &ComponentProvers<'_, SimdBackend>,
    rng: &mut ChaCha20Rng,
    channel: &mut MC::C,
) -> Result<SecureField, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let random_coeff = channel.draw_secure_felt();
    let composition_poly = provers.compute_composition_polynomial(
        random_coeff,
        &scheme.trace(),
        setup.twiddles,
        setup.format.params.log_blowup,
    );
    if composition_poly.log_size() != setup.composition {
        return Err(ProveError::Masking(
            "the composition polynomial is not at its bound",
        ));
    }
    let mut polys = composition_poly.into_coordinate_polys().to_vec();
    let seeds: Vec<[u8; 32]> = (0..setup.masking.fri_mask_columns)
        .map(|_| rng.r#gen())
        .collect();
    for seed in &seeds {
        drawn::note("an R column's seed", seed);
    }
    polys.extend(
        seeds
            .into_iter()
            .map(|seed| salts::uniform_poly(seed, setup.composition)),
    );
    salts::commit_salted(
        scheme,
        polys,
        setup.lifting,
        setup.masking.salt_columns,
        rng,
        channel,
    );
    Ok(random_coeff)
}

/// `set`'s sample points around `oods_point`, checked to fit the committed
/// trees with no salt sampled.
fn checked_points<MC: MerkleChannel, R, A>(
    setup: &Setup<'_, '_, R, A>,
    set: &impl MaskedComponents,
    scheme: &Scheme<'_, MC>,
    oods_point: CirclePoint<SecureField>,
) -> Result<Points, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let points = air::sample_points(set, oods_point, &mask_pins(&setup.masking)).ok_or(
        ProveError::Masking("the set's mask points do not fit its trees"),
    )?;
    let fits = points.len() == scheme.trees.len()
        && points
            .iter()
            .zip(scheme.trees.iter())
            .all(|(columns, tree)| columns.len() == tree.polynomials.len());
    let salts_unsampled = points.iter().skip(1).all(|columns| {
        columns
            .len()
            .checked_sub(setup.masking.salt_columns)
            .is_some_and(|start| columns[start..].iter().all(Vec::is_empty))
    });
    if !fits || !salts_unsampled {
        return Err(ProveError::Masking(
            "the sample points do not fit the trees, or a salt is sampled",
        ));
    }
    Ok(points)
}

/// R1 on the transcript: the randomizer's revealed functionals at `points`
/// and the queried `query_positions`, timed. `None` when they are not of
/// full rank.
fn rank_check<R, A>(
    setup: &Setup<'_, '_, R, A>,
    components: &Components<'_>,
    points: &Points,
    oods_point: CirclePoint<SecureField>,
    query_positions: &[usize],
) -> Result<Option<R1>, ProveError> {
    let started = Instant::now();
    let revealed = rank::revealed_functionals(
        components,
        points,
        oods_point,
        query_positions,
        setup.lifting,
        setup.mask_rows,
    )
    .ok_or(ProveError::Masking(
        "R1's column classes do not fit the sample points",
    ))?;
    let took = started.elapsed();
    Ok(revealed.independent.then_some(R1 {
        took,
        classes: revealed.classes,
        rows: revealed.rows,
    }))
}

/// The blinding values (R2), one a component: zero for the components
/// `public` names, uniform for the others but the last, which makes them sum
/// to zero, so the claimed sums' total is the unblinded one. A set of one
/// blinded component is left unblinded.
fn blinding(n_components: usize, public: &[usize], rng: &mut ChaCha20Rng) -> Vec<SecureField> {
    let blinded: Vec<usize> = (0..n_components)
        .filter(|component| !public.contains(component))
        .collect();
    let drawn: Vec<SecureField> = (1..blinded.len())
        .map(|_| SecureField::from_m31_array(core::array::from_fn(|_| rng.r#gen())))
        .collect();
    let mut values = vec![SecureField::zero(); n_components];
    for (&component, &value) in blinded.iter().zip(&drawn) {
        values[component] = value;
    }
    if let Some(&last) = blinded.last() {
        values[last] = -drawn.iter().copied().sum::<SecureField>();
    }
    for value in &values {
        let limbs: Vec<u8> = value
            .to_m31_array()
            .iter()
            .flat_map(|limb| limb.0.to_le_bytes())
            .collect();
        drawn::note("a blinding value", &limbs);
    }
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
