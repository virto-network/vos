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
//! - **the DEEP batching** of every sampled value into one quotient by powers
//!   of one coefficient (`_get_batching_error`): `(B - 1) · ε_lin(k)`, `B` the
//!   sampled values;
//! - **each FRI fold** (`_get_commit_phase_error`): `(f - 1) · ε_lin(k / F_i)`,
//!   `f` the round's folding factor and `F_i` the product of the factors
//!   through it. Stwo folds the circle to the line once, then the line by
//!   `2^fold_step` a round, to the last layer;
//! - **ALI** (`circuits/deep_ali.py`, Theorem 8 of eprint 2022/1216):
//!   `L · C / |F|`, `C` the constraints combined by powers of one coefficient;
//! - **DEEP**: `L · (d·(k + c - 1) + (k - 1)) / (|F| - k - D)`, `k` the
//!   tallest trace column's length, `c` the most samples of one column,
//!   `D` the evaluation domain's size, and `d` the constraint degree, taken
//!   as `2^(l_C - l_k) + 1` with `l_C` the composition polynomial's log degree
//!   bound and `l_k = log2 k`. Stwo bounds a component of `2^l` rows whose
//!   constraints have degree `d_i` by `2^l · 2^⌈log2(d_i - 1)⌉ ≤ 2^l_C`, so
//!   `d_i · 2^l ≤ 2^l_C + k = d · k`: the term is counted at a degree at least
//!   every component's, exact for degree 2 and 3 when the tallest component
//!   sets `l_C`, and larger otherwise, which only lowers the count;
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
//! The arithmetic is IEEE-754 double precision with only the basic operations,
//! so every verifier computes the same counts.

use crate::format::FormatParams;

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
    /// Every sampled value the DEEP quotient batches, `B`.
    pub sampled_values: u64,
    /// The most samples of one column, `c`.
    pub max_samples_per_column: u64,
    /// The constraints combined into the composition polynomial, `C`.
    pub constraints: u64,
    /// An upper bound on the logup fractions over all rows, `N`.
    pub logup_fractions: u64,
    /// The widest relation's tuple, `S`.
    pub relation_width: u64,
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
    // `query(m)` rises with `m` and `rest(m)` falls, so their least is
    // unimodal: find the first `m` where the query term reaches the rest.
    let (mut low, mut high) = (M_MIN, M_MAX);
    while low < high {
        let mid = low + (high - low) / 2;
        if analysis.query_bits(mid) >= analysis.other_bits(mid) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let best = [low.saturating_sub(1).max(M_MIN), low]
        .into_iter()
        .map(|m| analysis.bits_at(m))
        .fold(f64::NEG_INFINITY, f64::max);
    (best.is_finite() && best >= 0.0).then_some(best)
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

struct Analysis {
    rho: f64,
    sqrt_rho: f64,
    log_k: u32,
    log_blowup: u32,
    queries: f64,
    pow_bits: f64,
    /// `log2` of each fold's factor, the circle fold first.
    folds: alloc::vec::Vec<u32>,
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
        let mut folds = alloc::vec![1];
        let mut remaining = shape.log_degree_bound - 1 - params.log_last_layer;
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

    /// The least of every term but the query phase's.
    fn other_bits(&self, m: u32) -> f64 {
        let shape = &self.shape;
        let field = field_size();
        let batching = (shape.sampled_values.saturating_sub(1).max(1) as f64)
            * self.linear_error(m, self.log_k);
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
        let deep = list
            * (degree * (k + shape.max_samples_per_column.max(1) as f64 - 1.0) + (k - 1.0))
            / (field - k - domain);
        let logup = shape.logup_fractions.max(1) as f64 * shape.relation_width.max(1) as f64
            / field
            * pow2(-(self.interaction_pow_bits as i32));
        [batching, folds, ali, deep, logup]
            .into_iter()
            .map(|error| -log2(error))
            .fold(f64::INFINITY, f64::min)
    }

    fn bits_at(&self, m: u32) -> f64 {
        let query = self.query_bits(m);
        let other = self.other_bits(m);
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
        };
        let analysis = Analysis::new(&params, &shape).unwrap();
        let at = |m| analysis.query_bits(m);
        assert!(at(M_MAX) < 64.0 && at(M_MAX) > 63.99);
        assert!(at(3) < at(30) && at(30) < at(300));
    }
}
