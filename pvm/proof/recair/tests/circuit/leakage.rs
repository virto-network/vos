//! The masking's statistical leakage gates on a small circuit
//! (`docs/design/proving.md` §5), at N proofs a witness: 64 in
//! `just check`; under `heavy-gates`, 500 in `just test-proof` and 2,000 in
//! `just slice-gate` (`LEAKAGE_N`).
//!
//! - **Witness indistinguishability:** the honest prover's published values
//!   do not depend on the witness. N proofs of one witness against N of
//!   another under the same public inputs (a zero witness and a random one;
//!   two amounts differing by 1): per field a two-sample χ² on 16 buckets
//!   of the value's top bits (4 at N ≤ 64), and one pooled two-sample KS
//!   over every value. The control: the unmasked prover fails the same
//!   test.
//! - **Uniformity:** each field of the zero witness's N proofs
//!   against uniform M31, one-sample χ² (exact at N ≤ 64).
//!
//! Their power [est; simulated at N = 2,000, scaled to other N by √N]: at
//! N = 2,000 the per-field χ² finds, with 90% power, a leak spread over the
//! buckets at total variation 0.133 and one concentrated in a bucket at
//! 0.081, and the pooled KS a common shift of the CDF of about 1.9·10^-3;
//! at N = 500 (`test-proof`), about 0.27 spread, 0.16 concentrated and a
//! shift of 3.8·10^-3; at N = 64 only a concentrated leak of 0.73 or more.
//! A regression guard against gross leaks, not evidence of zero knowledge.
//!
//! The family's error rate is 10^-3, Bonferroni over every field
//! (`common::leakage`). The proofs are seeded, one seed a proof, so a run
//! is reproducible; the seed is hashed with the witness's digest (R4), so
//! two witnesses' proofs never share a stream.

use std::sync::OnceLock;

use rayon::prelude::*;

use crate::common::Rng;
use crate::common::leakage::{
    Fields, Verdicts, chi2_survival, chi2_two_sample, chi2_uniform, exact_uniform_tail,
    indistinguishable, ks_two_sample, published, uniform,
};
use crate::masked_prover::format;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use vos_pvm_proof::format::Format;
use vos_pvm_recair::gadgets::{TranscriptGadget, leaf_hash};
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair::prove::{prove_masked_on, prove_on};
use vos_pvm_recair::{Context, Finalized, circuit_commitment};

/// The proofs a witness: 64 in `just check`; under `heavy-gates`,
/// `LEAKAGE_N` proofs, [`MEDIUM`] unless it is set.
pub(crate) fn n() -> usize {
    #[cfg(feature = "heavy-gates")]
    {
        static N: OnceLock<usize> = OnceLock::new();
        *N.get_or_init(|| crate::common::leakage::heavy_n("LEAKAGE_N", MEDIUM))
    }
    #[cfg(not(feature = "heavy-gates"))]
    {
        64
    }
}

/// The proofs a witness `just test-proof` takes; `just slice-gate` sets
/// `LEAKAGE_N` to 2,000.
#[cfg(feature = "heavy-gates")]
const MEDIUM: usize = 500;

/// The private circuit's witness: four private QM31 values.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Witness([SecureField; 4]);

impl Witness {
    pub(crate) fn zero() -> Self {
        Self([SecureField::default(); 4])
    }

    pub(crate) fn random(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        Self(core::array::from_fn(|_| rng.qm31()))
    }

    /// The amount one more: the first value's first limb plus 1.
    pub(crate) fn plus_one(self) -> Self {
        let mut values = self.0;
        values[0] += SecureField::from(BaseField::from(1));
        Self(values)
    }
}

/// A circuit over four private values through every gate (products, a
/// fused multiply-add, a pointwise product, a limb, an `h8` step, a Merkle
/// leaf and a transcript over them), whose outputs do not depend on them
/// (`d − d` and `one`): every witness has the same circuit and the same
/// public inputs.
pub(crate) fn private_circuit(witness: &Witness) -> Finalized<SecureField> {
    let mut context = Context::<SecureField>::with_outputs(2);
    let x: Vec<_> = witness
        .0
        .iter()
        .map(|&value| context.guess(value))
        .collect();
    let product = context.mul(x[0], x[1]);
    let sum = context.mul_add(x[2], x[3], product);
    let pointwise = context.pointwise_mul(sum, x[0]);
    let limb = context.limb(pointwise, 2);
    let step = context.h8(x[0], x[1], x[2], [x[3], limb]);
    let leaf = leaf_hash(&mut context, &[x[0], x[1], sum, step], 16);
    let mut transcript = TranscriptGadget::new(&context);
    transcript.absorb(&mut context, &leaf.digest, 8);
    let [drawn, _] = transcript.squeeze(&mut context);
    let mixed = context.add(drawn, x[3]);
    let zero = context.sub(mixed, mixed);
    let one = context.one();
    context.set_outputs(&[zero, one]);
    context
        .finalize_to(Some([1 << 8; 3]))
        .expect("the wiring checks")
}

/// `n` masked proofs of `witness`'s circuit, seed `i` for proof `i`, their
/// published values by field.
fn masked(witness: &Witness, n: usize) -> Fields {
    let finalized = private_circuit(witness);
    let format = format();
    (0..n as u64)
        .into_par_iter()
        .fold(Fields::default, |mut fields, seed| {
            let (proof, _) = prove_masked_on::<Blake2bMerkleChannel>(
                &format,
                &finalized.circuit,
                &finalized.witness,
                MaskRng::Seeded(seed),
                |_| {},
            )
            .expect("proves");
            fields.add(&published(&proof.stark_proof, &proof.claimed_sums));
            fields
        })
        .reduce(Fields::default, Fields::merge)
}

/// `n` proofs of `witness`'s circuit by the unmasked prover at the small
/// format's parameters: deterministic, so one proof `n` times.
fn unmasked(witness: &Witness, n: usize) -> Fields {
    let finalized = private_circuit(witness);
    let format = Format {
        masked: false,
        masking: None,
        ..format()
    };
    let proof =
        prove_on::<Blake2bMerkleChannel>(&format, &finalized.circuit, &finalized.witness, |_| {})
            .expect("proves");
    let fields = published(&proof.stark_proof, &proof.claimed_sums);
    let mut all = Fields::default();
    for _ in 0..n {
        all.add(&fields);
    }
    all
}

/// The three witnesses' masked proofs, shared by the tests: the zero
/// witness, a random one, and the random one's amount plus 1.
fn witnesses() -> &'static [Fields; 3] {
    static PROOFS: OnceLock<[Fields; 3]> = OnceLock::new();
    PROOFS.get_or_init(|| {
        let random = Witness::random(1);
        let circuits =
            [Witness::zero(), random, random.plus_one()].map(|w| private_circuit(&w).circuit);
        let commitment = circuit_commitment(&circuits[0]).unwrap();
        for circuit in &circuits {
            assert_eq!(
                circuit_commitment(circuit).unwrap(),
                commitment,
                "one circuit"
            );
        }
        let started = std::time::Instant::now();
        let proofs = [Witness::zero(), random, random.plus_one()].map(|w| masked(&w, n()));
        eprintln!(
            "{} masked proofs of each of 3 witnesses in {:.1}s, {} fields each",
            n(),
            started.elapsed().as_secs_f64(),
            proofs[0].0.len()
        );
        proofs
    })
}

/// The statistics against known values: χ²'s survival function at its
/// tabled quantiles, the two-sample tests of one sample against itself and
/// of disjoint samples, and the one-sample test of an even spread.
#[test]
fn the_statistics_are_calibrated() {
    for (x, df, p) in [
        (3.841_459, 1.0, 0.05),
        (30.577_914, 15.0, 0.01),
        (37.697_298, 15.0, 0.001),
        (24.995_790, 15.0, 0.05),
    ] {
        let survival = chi2_survival(x, df);
        assert!(
            (survival - p).abs() < p * 1e-4,
            "χ²({df}) at {x}: {survival}"
        );
    }
    let even: Vec<u32> = (0..1u32 << 12).map(|i| i << 19).collect();
    assert!(chi2_uniform(&even) > 0.99);
    assert!(chi2_two_sample(&even, &even) > 0.99);
    assert!(ks_two_sample(even.clone(), even.clone()) > 0.99);
    let low: Vec<u32> = (0..64).collect();
    let high: Vec<u32> = (0..64).map(|i| (1 << 30) + i).collect();
    assert!(chi2_two_sample(&low, &high) < 1e-12);
    assert!(ks_two_sample(low.clone(), high) < 1e-12);
    assert!(chi2_uniform(&low) < 1e-12);
    // The exact tail: two draws over four buckets land in one with
    // probability 1/4 (`Σ o² = 4`), else in two (`Σ o² = 2`).
    let tail = exact_uniform_tail(2, 4);
    assert!((tail[0] - 1.0).abs() < 1e-12 && (tail[2] - 1.0).abs() < 1e-12);
    assert!((tail[3] - 0.25).abs() < 1e-12 && (tail[4] - 0.25).abs() < 1e-12);
    let tail = exact_uniform_tail(64, 4);
    assert!((tail[0] - 1.0).abs() < 1e-9, "{}", tail[0]);
}

/// Witness indistinguishability: the masked prover's published values do
/// not depend on the witness, for the zero witness against a random one and
/// for two amounts differing by 1; the unmasked prover fails the same test.
#[test]
fn the_masked_openings_do_not_depend_on_the_witness() {
    let [zero, random, amount] = witnesses();
    let mut verdicts = Verdicts::new("indistinguishability, the small circuit");
    indistinguishable(&mut verdicts, "zero/random", zero, random, n());
    indistinguishable(&mut verdicts, "amount/amount+1", random, amount, n());
    verdicts.report();
    let refused = verdicts.refused();
    assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);

    let mut control = Verdicts::new("indistinguishability's control, unmasked");
    indistinguishable(
        &mut control,
        "zero/random",
        &unmasked(&Witness::zero(), n()),
        &unmasked(&Witness::random(1), n()),
        n(),
    );
    control.report();
    assert!(!control.refused().is_empty(), "the unmasked prover passes");
}

/// Uniformity: each published field of the zero witness's masked proofs is
/// uniform over M31.
#[test]
fn the_masked_openings_are_uniform() {
    let [zero, ..] = witnesses();
    let mut verdicts = Verdicts::new("uniformity, the small circuit");
    uniform(&mut verdicts, zero, n());
    verdicts.report();
    let refused = verdicts.refused();
    assert!(refused.is_empty(), "{:?}", &refused[..refused.len().min(8)]);
}
