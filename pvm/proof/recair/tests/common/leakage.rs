//! The leakage gates' statistics (`docs/design/slice-6-on-chain.md`, step
//! 6.6): a masked proof's published values field by field, and the tests
//! they are held to, each with its p-value:
//! - per field, a two-sample χ² on 16 buckets of a value's top bits (two
//!   witnesses' proofs), or a one-sample χ² against uniform M31;
//! - over every value pooled, a two-sample Kolmogorov–Smirnov test.
//!
//! The family-wise error rate is [`ALPHA`] over every statistical test of
//! the gates ([`TESTS`] of them, a share each), split by Bonferroni over a
//! test's hypotheses. The tests guard against gross leaks (an unmasked
//! column, a reused mask, an unblinded sum); zero knowledge is the
//! argument's, R1 on every proof.

use std::collections::BTreeMap;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

/// The gates' family-wise error rate.
pub const ALPHA: f64 = 1e-3;

/// The statistical tests the family counts: on the small circuit, the
/// witness pairs and the uniformity; on the real wrap, the same two.
pub const TESTS: f64 = 4.0;

/// A field's place in a proof: its kind, its tree or FRI layer, its column
/// and its index there.
pub type Key = (Kind, usize, usize, usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// An out-of-domain sample's limb (index `4·sample + limb`).
    Sampled,
    /// A queried value, in the order of its query.
    Queried,
    /// A claimed sum's limb.
    Claimed,
    /// A FRI layer's witness value's limb (layer 0 the first).
    FriWitness,
    /// A limb of the FRI last layer's coefficient.
    FriLast,
}

/// Every M31 value a proof publishes beside its hashes and nonces, but the
/// preprocessed tree's (the circuit's, public): the samples and the queried
/// values of the main, interaction and composition trees, the claimed sums,
/// FRI's witness values and last layer.
pub fn published<H: MerkleHasherLifted>(
    stark: &StarkProof<H>,
    claimed_sums: &[SecureField],
) -> Vec<(Key, u32)> {
    let mut fields = Vec::new();
    let mut secure = |kind, at: usize, column: usize, values: &[SecureField]| {
        for (i, value) in values.iter().enumerate() {
            for (limb, word) in value.to_m31_array().into_iter().enumerate() {
                fields.push(((kind, at, column, 4 * i + limb), word.0));
            }
        }
    };
    for (tree, columns) in stark.sampled_values.iter().enumerate().skip(1) {
        for (column, samples) in columns.iter().enumerate() {
            secure(Kind::Sampled, tree, column, samples);
        }
    }
    secure(Kind::Claimed, 0, 0, claimed_sums);
    let fri = &stark.fri_proof;
    for (layer, proof) in std::iter::once(&fri.first_layer)
        .chain(&fri.inner_layers)
        .enumerate()
    {
        secure(Kind::FriWitness, layer, 0, &proof.fri_witness);
    }
    secure(Kind::FriLast, 0, 0, &fri.last_layer_poly);
    for (tree, columns) in stark.queried_values.iter().enumerate().skip(1) {
        for (column, values) in columns.iter().enumerate() {
            fields.extend(
                values
                    .iter()
                    .enumerate()
                    .map(|(i, value): (usize, &BaseField)| {
                        ((Kind::Queried, tree, column, i), value.0)
                    }),
            );
        }
    }
    fields
}

/// Proofs' fields gathered by key.
#[derive(Default)]
pub struct Fields(pub BTreeMap<Key, Vec<u32>>);

impl Fields {
    /// A proof's fields added.
    pub fn add(&mut self, proof: &[(Key, u32)]) {
        for &(key, value) in proof {
            self.0.entry(key).or_default().push(value);
        }
    }

    /// Two gatherings as one.
    pub fn merge(mut self, other: Self) -> Self {
        for (key, values) in other.0 {
            self.0.entry(key).or_default().extend(values);
        }
        self
    }

    /// Every value, pooled.
    pub fn pooled(&self) -> Vec<u32> {
        self.0.values().flatten().copied().collect()
    }
}

/// The 16 buckets of M31's top four bits.
fn buckets(values: &[u32]) -> [f64; 16] {
    let mut counts = [0.0; 16];
    for &value in values {
        counts[(value >> 27) as usize] += 1.0;
    }
    counts
}

/// The two-sample χ² test of two samples' buckets: the p-value that they
/// come from one distribution, at one degree of freedom fewer than the
/// buckets either sample fills.
pub fn chi2_two_sample(a: &[u32], b: &[u32]) -> f64 {
    let (r, s) = (buckets(a), buckets(b));
    let (total_r, total_s) = (a.len() as f64, b.len() as f64);
    let (k1, k2) = ((total_s / total_r).sqrt(), (total_r / total_s).sqrt());
    let mut statistic = 0.0;
    let mut filled = 0;
    for (r, s) in r.into_iter().zip(s) {
        if r + s > 0.0 {
            statistic += (k1 * r - k2 * s).powi(2) / (r + s);
            filled += 1;
        }
    }
    if filled < 2 {
        return 1.0;
    }
    chi2_survival(statistic, (filled - 1) as f64)
}

/// The one-sample χ² test of a sample's buckets against uniform M31: the
/// last bucket holds one value fewer than the others (`p = 2^31 − 1`).
pub fn chi2_uniform(values: &[u32]) -> f64 {
    let n = values.len() as f64;
    let p = f64::from(stwo::core::fields::m31::P);
    let statistic: f64 = buckets(values)
        .into_iter()
        .enumerate()
        .map(|(bucket, observed)| {
            let size = if bucket == 15 { (1 << 27) - 1 } else { 1 << 27 };
            let expected = n * f64::from(size) / p;
            (observed - expected).powi(2) / expected
        })
        .sum();
    chi2_survival(statistic, 15.0)
}

/// The two-sample Kolmogorov–Smirnov test: the p-value, asymptotic, that
/// `a` and `b` come from one distribution.
pub fn ks_two_sample(mut a: Vec<u32>, mut b: Vec<u32>) -> f64 {
    a.sort_unstable();
    b.sort_unstable();
    let (n, m) = (a.len() as f64, b.len() as f64);
    let (mut i, mut j, mut d) = (0, 0, 0.0f64);
    while i < a.len() && j < b.len() {
        let value = a[i].min(b[j]);
        while i < a.len() && a[i] == value {
            i += 1;
        }
        while j < b.len() && b[j] == value {
            j += 1;
        }
        d = d.max((i as f64 / n - j as f64 / m).abs());
    }
    let effective = (n * m / (n + m)).sqrt();
    let lambda = (effective + 0.12 + 0.11 / effective) * d;
    kolmogorov_survival(lambda)
}

/// `P(K > λ)` for Kolmogorov's distribution.
fn kolmogorov_survival(lambda: f64) -> f64 {
    if lambda < 0.2 {
        return 1.0;
    }
    let mut sum = 0.0;
    for k in 1..=200 {
        let k = f64::from(k);
        let term = (-2.0 * k * k * lambda * lambda).exp();
        sum += if k as u32 % 2 == 1 { term } else { -term };
        if term < 1e-300 {
            break;
        }
    }
    (2.0 * sum).clamp(0.0, 1.0)
}

/// `P(X > x)` for `X ~ χ²` of `df` degrees of freedom: the regularized upper
/// incomplete gamma function `Q(df/2, x/2)`.
pub fn chi2_survival(x: f64, df: f64) -> f64 {
    gamma_q(df / 2.0, x / 2.0)
}

fn gamma_q(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    let prefactor = (-x + a * x.ln() - ln_gamma(a)).exp();
    if x < a + 1.0 {
        // The series of P(a, x).
        let (mut term, mut sum, mut ap) = (1.0 / a, 1.0 / a, a);
        for _ in 0..10_000 {
            ap += 1.0;
            term *= x / ap;
            sum += term;
            if term.abs() < sum.abs() * 1e-16 {
                break;
            }
        }
        (1.0 - sum * prefactor).max(0.0)
    } else {
        // Lentz's continued fraction of Q(a, x).
        let tiny = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..10_000 {
            let i = f64::from(i);
            let an = -i * (i - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let delta = d * c;
            h *= delta;
            if (delta - 1.0).abs() < 1e-16 {
                break;
            }
        }
        prefactor * h
    }
}

/// `ln Γ(x)` for `x > 0`, Lanczos' approximation (g = 7, 9 terms).
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const COEFFICIENTS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        let pi = std::f64::consts::PI;
        return (pi / (pi * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut sum = COEFFICIENTS[0];
    for (i, &c) in COEFFICIENTS.iter().enumerate().skip(1) {
        sum += c / (x + i as f64);
    }
    let t = x + G + 0.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + sum.ln()
}

/// One test's verdicts: each hypothesis' name and p-value, and the
/// threshold Bonferroni sets for it.
pub struct Verdicts {
    pub name: &'static str,
    pub p_values: Vec<(String, f64)>,
}

impl Verdicts {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            p_values: Vec::new(),
        }
    }

    pub fn push(&mut self, hypothesis: String, p: f64) {
        self.p_values.push((hypothesis, p));
    }

    /// This test's share of the family's error rate, split over its
    /// hypotheses.
    pub fn threshold(&self) -> f64 {
        ALPHA / TESTS / self.p_values.len() as f64
    }

    /// The hypotheses refused at the threshold, the smallest p-values
    /// first.
    pub fn refused(&self) -> Vec<(String, f64)> {
        let threshold = self.threshold();
        let mut refused: Vec<(String, f64)> = self
            .p_values
            .iter()
            .filter(|(_, p)| *p < threshold)
            .cloned()
            .collect();
        refused.sort_by(|a, b| a.1.total_cmp(&b.1));
        refused
    }

    /// The smallest p-value and its hypothesis.
    pub fn smallest(&self) -> (String, f64) {
        self.p_values
            .iter()
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .cloned()
            .unwrap_or_default()
    }

    pub fn report(&self) {
        let (hypothesis, p) = self.smallest();
        eprintln!(
            "{}: {} hypotheses, threshold {:.2e}; the smallest p-value {p:.3e} ({hypothesis}); {} refused",
            self.name,
            self.p_values.len(),
            self.threshold(),
            self.refused().len()
        );
    }
}

/// Witness indistinguishability between two witnesses' proofs: per field a
/// two-sample χ² (a field with fewer than half the proofs' values on either
/// side left out), and one pooled two-sample KS over every value.
pub fn indistinguishable(verdicts: &mut Verdicts, label: &str, a: &Fields, b: &Fields, n: usize) {
    for (key, values) in &a.0 {
        let Some(others) = b.0.get(key) else {
            continue;
        };
        if 2 * values.len() < n || 2 * others.len() < n {
            continue;
        }
        verdicts.push(
            format!("{label} χ² {key:?}"),
            chi2_two_sample(values, others),
        );
    }
    verdicts.push(
        format!("{label} pooled KS"),
        ks_two_sample(a.pooled(), b.pooled()),
    );
}

/// Uniformity: each field of `fields` against uniform M31, one-sample χ²
/// (a field with fewer than half the proofs' values left out).
pub fn uniform(verdicts: &mut Verdicts, fields: &Fields, n: usize) {
    for (key, values) in &fields.0 {
        if 2 * values.len() >= n {
            verdicts.push(format!("uniform χ² {key:?}"), chi2_uniform(values));
        }
    }
}
