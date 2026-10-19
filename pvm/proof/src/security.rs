//! A proof's two security counts, conjectured and proven, from its
//! parameters and its shape.
//!
//! **Conjectured bits** are `pow_bits + n_queries · log_blowup`: one bit a
//! query a blowup bit, the ethSTARK up-to-capacity conjecture (eprint
//! 2021/582, §5.10.2), which Diamond–Gruen (eprint 2025/2010) and
//! Crites–Stewart (eprint 2025/2046) refuted as stated.
//!
//! **Proven bits** are the Johnson-bound count of `soundcalc`
//! (`github.com/ethereum/soundcalc`, revision `2af5e7df`), the least of these
//! terms, each `-log2` of a soundness error:
//!
//! - **the query phase** (`pcs/fri.py`, `_get_query_phase_error`):
//!   `2^-pow_bits · (1 - γ)^n_queries`, with the proximity parameter
//!   `γ = 1 - √ρ - η` and the gap `η = √ρ / (2m)`;
//! - **the DEEP batching** of every sampled value into one quotient
//!   (`_get_batching_error`): by powers of one coefficient (Stwo's,
//!   [`DeepBatching::Powers`]), `(B - 1) · ε_lin(k)`, `B` the batched values,
//!   the proximity gap for curves (BCIKS20 Theorem 6.2); with an independent
//!   coefficient a value ([`DeepBatching::Affine`]), `ε_lin(k)`, the gap for
//!   affine spaces (BCIKS20 Theorem 1.6), as `soundcalc` counts it.
//!   `soundcalc` calls the latter *linear batching* (`pcs.py`'s
//!   `_get_batching_error`, `johnson_bound.py`'s `get_error_linear`) and
//!   cites only BCHKS25; the BCIKS20 theorem names are ours, so an audit
//!   checks that Theorem 1.6's correlated agreement for affine spaces
//!   carries BCHKS25 Theorem 4.2's `ε_lin`, as `soundcalc` assumes;
//! - **each FRI fold** (`_get_commit_phase_error`): `(f - 1) · ε_lin(k / F_i)`,
//!   `f` the round's folding factor and `F_i` the product of the factors
//!   through it. Stwo's first round folds the circle to the line and the line
//!   `fold_step - 1` times before its first commitment, one round of factor
//!   `2^fold_step`; each later round folds by `2^fold_step`, the last by what
//!   remains, to the last layer (the fork's `DIVERGENCE-011`);
//! - **ALI** (`circuits/deep_ali.py`, Theorem 8 of eprint 2022/1216):
//!   `L · C / |F|`, `C` the constraints combined by powers of one coefficient;
//! - **DEEP**: `2^j · L · (d·(k + c - 1) + (k - 1)) / (|F| - k - D)`, `k`
//!   the tallest trace column's length, `c` the most values of one column,
//!   `D` the evaluation domain's size, and `d` the constraint degree, taken
//!   as `2^(l_C - l_k) + 1` with `l_C` the composition polynomial's log degree
//!   bound and `l_k = log2 k`. Stwo bounds a component of `2^l` rows whose
//!   constraints have degree `d_i` by `2^l · 2^⌈log2(d_i - 1)⌉ ≤ 2^l_C`, so
//!   `d_i · 2^l ≤ 2^l_C + k = d · k`: the term is counted at a degree at least
//!   every component's, exact for degree 2 and 3 when the tallest component
//!   sets `l_C`, and larger otherwise, which only lowers the count. `j` is
//!   how often the out-of-domain point is doubled before the composition is
//!   sampled there, 0 in Stwo's protocol: the identity is then checked at a
//!   point uniform on the circle's `j`-fold doubling image, `2^j` times
//!   smaller than the circle, so its error is at most `2^j` times larger;
//! - **logup** (`lookups/logup.py`, univariate): `N · S / |F|`, `N` the
//!   fractions over all rows and `S` the widest relation, times
//!   `2^-interaction_pow_bits`, the grind drawn before the relation
//!   challenges.
//!
//! `ε_lin(k)` is Theorem 4.2 of BCHKS25 (Ben-Sasson, Carmon, Haböck, Kopparty,
//! Saraf, "On Proximity Gaps for Reed–Solomon Codes", eprint 2025/2055), as
//! `proxgaps/johnson_bound.py` writes it, with `n = k / ρ` and `m' = m + ½`:
//!
//! ```text
//! ε_lin(k) = ( (2·m'^5 + 3·m'·γ·ρ) · n / (3·ρ·√ρ) + m' / √ρ ) / |F|
//! ```
//!
//! The list size `L` is the larger of the two `soundcalc` gives,
//! `(m + ½) / √ρ` and `1 / (2·η·√ρ) = m / ρ`. The field is QM31,
//! `|F| = (2^31 - 1)^4`. The multiplicity `m ≥ 3` (BCHKS25 Theorem 4.2) is the
//! analysis's to choose: a larger `m` narrows the gap, so the query term rises
//! while every other term falls, and the count is taken at the `m` that
//! maximizes the least term.
//!
//! The analysis refuses a shape outside soundcalc's multi-point precondition
//! (`circuits/deep_ali.py`), `k + c < (1 - θ)·n` with `k` the dimension FRI
//! tests, `n = k / ρ` and `θ` the proximity parameter `γ`. It is checked at
//! `γ`'s limit, `1 - γ > √ρ` for every `m`, so it holds at whatever `m` the
//! count is taken.
//!
//! **Masking variant (c)** ([`SecurityShape::variant_c`],
//! `research/slice-5/spike2-masking.md` §3b) moves an AIR whose tallest
//! component has `N = 2^m` rows to other levels; every formula stays.
//! Every main and interaction column is committed as `f + v_H·r`, of degree
//! bound `2N`, so `k = 2N` in the DEEP term. The constraint bound is `4N`
//! and the composition is committed whole, never split, so FRI tests
//! dimension `4N` at the format's rate (FRI's `log_blowup`), and `d = 3`.
//! The composition is sampled at `π(z)`, the doubling of the out-of-domain
//! point, so `j = 1`. The masked columns, the FRI mask and the blinding
//! columns are batched with the rest: an affine batch's error does not
//! depend on how many functions it batches, and a batch by powers counts
//! them in `B`. Salt columns are never sampled and enter no term. A masked
//! shape is read from its own layout: `framework_access`' shape subtracts
//! Stwo's composition split, which would put FRI's dimension at `2N`
//! (`log_degree_bound` `m+1`).
//!
//! The arithmetic is IEEE-754 double precision with only the basic operations,
//! so every verifier computes the same counts.

use crate::format::{DeepBatching, FormatParams};

/// The proof shape the proven count depends on, beside the format's
/// parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityShape {
    /// `log2` of the degree bound FRI tests, `k`: the lifted composition
    /// columns' (`max_log_degree_bound`).
    pub log_degree_bound: u32,
    /// `log2` of the tallest trace column's length.
    pub log_trace_length: u32,
    /// `log2` of the composition polynomial's degree bound.
    pub log_composition_degree_bound: u32,
    /// Every value the DEEP quotient batches, `B`: each sample, and for a
    /// column sampled at two points (one read at the previous row) the
    /// periodicity value the batch adds, one coefficient each (the fork's
    /// `deep_values_of_column`).
    pub sampled_values: u64,
    /// The most values of one column, `c`, counted as `sampled_values`
    /// counts them: 3 for a column sampled at two points, whose periodicity
    /// value is an opening at a third.
    pub max_samples_per_column: u64,
    /// The constraints combined into the composition polynomial, `C`.
    pub constraints: u64,
    /// An upper bound on the logup fractions over all rows, `N`.
    pub logup_fractions: u64,
    /// The widest relation's tuple, `S`.
    pub relation_width: u64,
    /// How often the out-of-domain point is doubled before the composition
    /// is sampled there, `j`: 0 in Stwo's protocol, 1 under masking variant
    /// (c).
    pub composition_point_doublings: u32,
}

impl SecurityShape {
    /// The same AIR proved under masking variant (c), from its tallest
    /// component's `2^m` rows (`log_trace_length`): its columns masked to
    /// degree bound `2^(m+1)`, its composition whole at `2^(m+2)`, which FRI
    /// tests, and sampled at `π(z)`. Only the levels move: what the masking
    /// commits beside the AIR's columns (the blinding columns, the FRI mask,
    /// the composition's columns whole rather than split) and the blinding's
    /// constraints and fractions are the caller's to add.
    pub const fn variant_c(self) -> Self {
        let m = self.log_trace_length;
        Self {
            log_degree_bound: m + 2,
            log_trace_length: m + 1,
            log_composition_degree_bound: m + 2,
            composition_point_doublings: 1,
            ..self
        }
    }
}

/// A proof's two counts, in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityBits {
    pub conjectured: u32,
    pub proven: u32,
}

/// `pow_bits + n_queries · log_blowup`, `None` on overflow.
pub fn conjectured_bits(params: &FormatParams) -> Option<u32> {
    let queries = u32::try_from(params.n_queries).ok()?;
    params
        .pow_bits
        .checked_add(queries.checked_mul(params.log_blowup)?)
}

/// Both counts, `None` for parameters outside the analysis (a blowup of 0
/// or above 30, a degree bound outside the M31 circle, no queries, a shape
/// outside the multi-point precondition).
pub fn security_bits(params: &FormatParams, shape: &SecurityShape) -> Option<SecurityBits> {
    Some(SecurityBits {
        conjectured: conjectured_bits(params)?,
        proven: proven_bits(params, shape)?,
    })
}

/// The proven count, the floor of [`proven_count`].
pub fn proven_bits(params: &FormatParams, shape: &SecurityShape) -> Option<u32> {
    proven_count(params, shape).map(|bits| bits as u32)
}

/// The proven count unrounded: the least term at the best `m`, `None` for a
/// shape outside the analysis or a count below 0.
pub fn proven_count(params: &FormatParams, shape: &SecurityShape) -> Option<f64> {
    let analysis = Analysis::new(params, shape)?;
    let (_, best) = analysis.best();
    (best.is_finite() && best >= 0.0).then_some(best)
}

/// `log2` of each FRI round's folding factor the count is taken at, the
/// first round's with the circle fold in it; `None` for a shape outside the
/// analysis. A verifier's own rounds must be these (format 39's: `[3, 3, 3,
/// 2]`, `vos_pvm_final_verifier::masked::FRI_ROUNDS`).
pub fn fri_rounds(params: &FormatParams, shape: &SecurityShape) -> Option<alloc::vec::Vec<u32>> {
    Analysis::new(params, shape).map(|analysis| analysis.folds)
}

/// Each term in bits at the multiplicity the proven count is taken at.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct TermBits {
    pub m: u32,
    pub query: f64,
    pub other: OtherTerms,
}

/// [`TermBits`] for `params` at `shape`, `None` outside the analysis.
#[cfg(test)]
pub(crate) fn term_bits(params: &FormatParams, shape: &SecurityShape) -> Option<TermBits> {
    let analysis = Analysis::new(params, shape)?;
    let (m, _) = analysis.best();
    Some(TermBits {
        m,
        query: analysis.query_bits(m),
        other: analysis.other_terms(m),
    })
}

/// BCHKS25 Theorem 4.2 takes `m ≥ 3`.
const M_MIN: u32 = 3;
/// Far past where any term balances for our parameters.
const M_MAX: u32 = 1 << 20;

/// `|F|` of QM31, `(2^31 - 1)^4`.
fn field_size() -> f64 {
    let p = ((1u64 << 31) - 1) as f64;
    p * p * p * p
}

/// Every term but the query phase's, in bits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OtherTerms {
    /// The DEEP batching.
    pub batching: f64,
    /// The worst FRI fold.
    pub folds: f64,
    pub ali: f64,
    pub deep: f64,
    pub logup: f64,
}

impl OtherTerms {
    fn least(&self) -> f64 {
        [self.batching, self.folds, self.ali, self.deep, self.logup]
            .into_iter()
            .fold(f64::INFINITY, f64::min)
    }
}

struct Analysis {
    rho: f64,
    sqrt_rho: f64,
    log_k: u32,
    log_blowup: u32,
    queries: f64,
    pow_bits: f64,
    /// `log2` of each round's folding factor, the first round's with the
    /// circle fold in it.
    folds: alloc::vec::Vec<u32>,
    batching: DeepBatching,
    shape: SecurityShape,
    interaction_pow_bits: f64,
}

impl Analysis {
    fn new(params: &FormatParams, shape: &SecurityShape) -> Option<Self> {
        if !(1..=30).contains(&params.log_blowup)
            || params.n_queries == 0
            || shape.log_degree_bound > 30
            || shape.log_trace_length > shape.log_composition_degree_bound
            || shape.log_degree_bound <= params.log_last_layer
            || shape.composition_point_doublings > shape.log_degree_bound
            || params.fold_step == 0
        {
            return None;
        }
        let sqrt_rho = if params.log_blowup.is_multiple_of(2) {
            pow2(-(params.log_blowup as i32 / 2))
        } else {
            pow2(-(params.log_blowup as i32 / 2)) * core::f64::consts::FRAC_1_SQRT_2
        };
        // The multi-point precondition, `k + c < (1 - θ)·n`, at `θ`'s limit.
        let dimension = pow2(shape.log_degree_bound as i32);
        let domain = pow2((shape.log_degree_bound + params.log_blowup) as i32);
        if dimension + shape.max_samples_per_column as f64 >= sqrt_rho * domain {
            return None;
        }
        let mut folds = alloc::vec::Vec::new();
        let mut remaining = shape.log_degree_bound.checked_sub(params.log_last_layer)?;
        while remaining > 0 {
            let step = params.fold_step.min(remaining);
            folds.push(step);
            remaining -= step;
        }
        Some(Self {
            rho: pow2(-(params.log_blowup as i32)),
            sqrt_rho,
            log_k: shape.log_degree_bound,
            log_blowup: params.log_blowup,
            queries: params.n_queries as f64,
            pow_bits: f64::from(params.pow_bits),
            folds,
            batching: params.batching,
            shape: *shape,
            interaction_pow_bits: f64::from(params.interaction_pow_bits),
        })
    }

    fn eta(&self, m: u32) -> f64 {
        self.sqrt_rho / (2.0 * f64::from(m))
    }

    fn gamma(&self, m: u32) -> f64 {
        1.0 - self.sqrt_rho - self.eta(m)
    }

    fn list_size(&self, m: u32) -> f64 {
        let m = f64::from(m);
        let bchks = (m + 0.5) / self.sqrt_rho;
        let johnson = m / self.rho;
        if bchks > johnson { bchks } else { johnson }
    }

    /// `ε_lin` at dimension `2^log_dimension`.
    fn linear_error(&self, m: u32, log_dimension: u32) -> f64 {
        let shifted = f64::from(m) + 0.5;
        let n = pow2((log_dimension + self.log_blowup) as i32);
        let fifth = shifted * shifted * shifted * shifted * shifted;
        let first = (2.0 * fifth + 3.0 * shifted * self.gamma(m) * self.rho) * n
            / (3.0 * self.rho * self.sqrt_rho);
        let second = shifted / self.sqrt_rho;
        (first + second) / field_size()
    }

    fn query_bits(&self, m: u32) -> f64 {
        self.pow_bits - self.queries * log2(1.0 - self.gamma(m))
    }

    /// The multiplicity the count is taken at, and the count there.
    /// `query(m)` rises with `m` and the rest falls, so their least is
    /// unimodal: the best `m` is the first where the query term reaches the
    /// rest, or the one before it.
    fn best(&self) -> (u32, f64) {
        let (mut low, mut high) = (M_MIN, M_MAX);
        while low < high {
            let mid = low + (high - low) / 2;
            if self.query_bits(mid) >= self.other_terms(mid).least() {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        [low.saturating_sub(1).max(M_MIN), low]
            .into_iter()
            .map(|m| (m, self.bits_at(m)))
            .fold((M_MIN, f64::NEG_INFINITY), |best, at| {
                if at.1 > best.1 { at } else { best }
            })
    }

    fn other_terms(&self, m: u32) -> OtherTerms {
        let shape = &self.shape;
        let field = field_size();
        let batched = match self.batching {
            DeepBatching::Powers => shape.sampled_values.saturating_sub(1).max(1) as f64,
            DeepBatching::Affine => 1.0,
        };
        let batching = batched * self.linear_error(m, self.log_k);
        let mut folded = 0;
        let mut folds = 0.0f64;
        for &log_factor in &self.folds {
            folded += log_factor;
            let error = (pow2(log_factor as i32) - 1.0)
                * self.linear_error(m, self.log_k.saturating_sub(folded));
            if error > folds {
                folds = error;
            }
        }
        let list = self.list_size(m);
        let ali = list * shape.constraints.max(1) as f64 / field;
        let k = pow2(shape.log_trace_length as i32);
        let degree =
            pow2((shape.log_composition_degree_bound - shape.log_trace_length) as i32) + 1.0;
        let domain = pow2((shape.log_degree_bound + self.log_blowup) as i32);
        let deep = pow2(shape.composition_point_doublings as i32)
            * list
            * (degree * (k + shape.max_samples_per_column.max(1) as f64 - 1.0) + (k - 1.0))
            / (field - k - domain);
        let logup = shape.logup_fractions.max(1) as f64 * shape.relation_width.max(1) as f64
            / field
            * pow2(-(self.interaction_pow_bits as i32));
        OtherTerms {
            batching: -log2(batching),
            folds: -log2(folds),
            ali: -log2(ali),
            deep: -log2(deep),
            logup: -log2(logup),
        }
    }

    fn bits_at(&self, m: u32) -> f64 {
        let query = self.query_bits(m);
        let other = self.other_terms(m).least();
        if query < other { query } else { other }
    }
}

/// `2^exponent` for an exponent within the normal range.
fn pow2(exponent: i32) -> f64 {
    f64::from_bits(((exponent + 1023) as u64) << 52)
}

/// `log2(x)` for a positive normal `x`, to 2^-48, by the binary expansion of
/// the mantissa's logarithm (squaring and halving), with the basic operations
/// alone.
fn log2(x: f64) -> f64 {
    let bits = x.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut mantissa = f64::from_bits((bits & ((1u64 << 52) - 1)) | (1023u64 << 52));
    let mut result = exponent as f64;
    let mut bit = 0.5;
    for _ in 0..48 {
        mantissa *= mantissa;
        if mantissa >= 2.0 {
            mantissa /= 2.0;
            result += bit;
        }
        bit /= 2.0;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_is_exact_on_powers_of_two_and_close_elsewhere() {
        for exponent in [-200, -124, -1, 0, 1, 52, 300] {
            assert_eq!(log2(pow2(exponent)), f64::from(exponent));
        }
        let three = log2(3.0);
        assert!((three - 1.584_962_500_721_156).abs() < 1e-12, "{three}");
        let near_one = log2(0.5125);
        assert!(
            (near_one + 0.964_376_090_269_279_7).abs() < 1e-12,
            "{near_one}"
        );
    }

    /// A column sampled at more points than the precondition allows is
    /// outside the analysis.
    #[test]
    fn the_multi_point_precondition_refuses() {
        let params = FormatParams {
            log_blowup: 1,
            n_queries: 84,
            pow_bits: 20,
            fold_step: 1,
            log_last_layer: 0,
            interaction_pow_bits: 8,
            batching: DeepBatching::Powers,
        };
        let shape = |max_samples_per_column| SecurityShape {
            log_degree_bound: 4,
            log_trace_length: 4,
            log_composition_degree_bound: 5,
            sampled_values: 8,
            max_samples_per_column,
            constraints: 1,
            logup_fractions: 1,
            relation_width: 1,
            composition_point_doublings: 0,
        };
        // k = 16, n = 32, √ρ·n ≈ 22.6: c = 6 passes, c = 7 does not.
        assert!(proven_count(&params, &shape(6)).is_some());
        assert!(proven_count(&params, &shape(7)).is_none());
    }

    /// The query term alone, against the closed form: at a large `m` the gap
    /// vanishes and each query gives `log_blowup / 2` bits.
    #[test]
    fn the_query_term_tends_to_half_the_blowup_bits_a_query() {
        let params = FormatParams {
            log_blowup: 2,
            n_queries: 44,
            pow_bits: 20,
            fold_step: 1,
            log_last_layer: 0,
            interaction_pow_bits: 8,
            batching: DeepBatching::Powers,
        };
        let shape = SecurityShape {
            log_degree_bound: 20,
            log_trace_length: 20,
            log_composition_degree_bound: 21,
            sampled_values: 1,
            max_samples_per_column: 1,
            constraints: 1,
            logup_fractions: 1,
            relation_width: 1,
            composition_point_doublings: 0,
        };
        let analysis = Analysis::new(&params, &shape).unwrap();
        let at = |m| analysis.query_bits(m);
        assert!(at(M_MAX) < 64.0 && at(M_MAX) > 63.99);
        assert!(at(3) < at(30) && at(30) < at(300));
    }

    /// Stwo's first round folds by `2^fold_step`, the circle fold among
    /// them; later rounds by `2^fold_step`, the last by what remains. At fold
    /// step 1 that is one fold a round, as before.
    #[test]
    fn the_rounds_fold_as_stwo_folds() {
        let params = |fold_step, log_last_layer| FormatParams {
            log_blowup: 6,
            n_queries: 20,
            pow_bits: 26,
            fold_step,
            log_last_layer,
            interaction_pow_bits: 8,
            batching: DeepBatching::Affine,
        };
        let shape = SecurityShape {
            log_degree_bound: 16,
            log_trace_length: 15,
            log_composition_degree_bound: 17,
            sampled_values: 916,
            max_samples_per_column: 2,
            constraints: 313,
            logup_fractions: 1 << 20,
            relation_width: 5,
            composition_point_doublings: 0,
        };
        let folds = |fold_step, log_last_layer| {
            Analysis::new(&params(fold_step, log_last_layer), &shape)
                .unwrap()
                .folds
        };
        assert_eq!(folds(3, 6), [3, 3, 3, 1]);
        assert_eq!(folds(3, 7), [3, 3, 3]);
        assert_eq!(folds(1, 0), [1; 16]);
        assert_eq!(folds(4, 0), [4; 4]);
        // Under variant (c) the wrap's FRI tests 2^17: one round more.
        let masked = Analysis::new(&params(3, 6), &shape.variant_c()).unwrap();
        assert_eq!(masked.log_k, 17);
        assert_eq!(masked.folds, [3, 3, 3, 2]);
    }

    /// Variant (c) moves the levels and doubles the DEEP term, and nothing
    /// else: a `j` above the degree bound is refused.
    #[test]
    fn variant_c_moves_the_levels_and_doubles_the_deep_term() {
        let params = FormatParams {
            log_blowup: 5,
            n_queries: 24,
            pow_bits: 26,
            fold_step: 3,
            log_last_layer: 6,
            interaction_pow_bits: 8,
            batching: DeepBatching::Affine,
        };
        let shape = SecurityShape {
            log_degree_bound: 16,
            log_trace_length: 15,
            log_composition_degree_bound: 17,
            sampled_values: 916,
            max_samples_per_column: 2,
            constraints: 313,
            logup_fractions: 1 << 20,
            relation_width: 5,
            composition_point_doublings: 0,
        };
        let masked = shape.variant_c();
        assert_eq!(
            masked,
            SecurityShape {
                log_degree_bound: 17,
                log_trace_length: 16,
                log_composition_degree_bound: 17,
                composition_point_doublings: 1,
                ..shape
            }
        );
        let deep =
            |shape: &SecurityShape| Analysis::new(&params, shape).unwrap().other_terms(5).deep;
        let doubled = deep(&SecurityShape {
            composition_point_doublings: 0,
            ..masked
        }) - deep(&masked);
        assert!((doubled - 1.0).abs() < 1e-9, "{doubled}");
        let unreachable = SecurityShape {
            composition_point_doublings: 18,
            ..masked
        };
        assert!(proven_count(&params, &unreachable).is_none());
    }
}
