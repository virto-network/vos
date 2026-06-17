//! Recursion build P4.1 — the **DEEP-quotient chip**: the per-query FRI quotient
//! (`fri_answers` / `accumulate_row_quotients`) re-evaluated in-AIR.
//!
//! After the OODS DEEP-ALI check, stwo's verifier builds the first-layer FRI
//! evals from the trace's `queried_values` via `fri_answers`
//! (`core/pcs/quotients.rs:120`). For each query position `p` it accumulates,
//! over every sample point `z` and column `i`, the FRI quotient
//!
//! ```text
//!   Σ_z ( Σ_i (queried_i · c − (a · p.y + b)) ) · denom_inverse(z, p)
//! ```
//!
//! where `(a, b, c) = complex_conjugate_line_coeffs((z, sample_value_i), α^i)`
//! (`core/constraints.rs:119`) — the line through `(z, value_i)` and its
//! conjugate, scaled by the DEEP `random_coeff` power `α^i` — and
//! `denom_inverse ∈ CM31` is the conjugate-line quotient
//! (`quotients.rs:253 denominator_inverses`). This is the bridge from the trace
//! query openings to the FRI first layer (step E2 in `docs/plans/recursion-p4.md`).
//!
//! This chip arithmetizes `accumulate_row_quotients` (QM31-over-4×M31, the
//! `oods_composition_chip.rs`/`qm31_constraints.rs` idiom — all witnessed
//! products, degree ≤ 2) for one sample batch (the OODS point) over
//! `N_DQ_COLS` columns:
//!   * the OODS point + the DEEP coeff `α` + the columns' sampled values are
//!     EXTRACTED from a real Poseidon2-M31 inner proof by replicating the
//!     verifier transcript (same pattern as `oods_composition_chip.rs::extract`);
//!   * `α^i` is chained in-AIR (αpow₀ = 1, αpowᵢ = αpowᵢ₋₁·α);
//!   * `(aᵢ, bᵢ, cᵢ)` are re-derived in-AIR (`complex_conjugate` = negate QM31
//!     coords 2,3; the products witnessed);
//!   * the row quotient is accumulated and the final `numerator·denom_inverse`
//!     (a QM31·CM31 mul, done as a QM31 mul by `denomᵢ` embedded as `[d0,d1,0,0]`)
//!     is asserted equal to stwo's own `accumulate_row_quotients` output.
//!
//! GREEN GATE: the in-AIR re-evaluation matches stwo's `accumulate_row_quotients`
//! on real OODS data, proves+verifies through the lifted Poseidon2-M31 protocol,
//! and a perturbed queried value is rejected. (The full multi-tree aggregation
//! over all query positions is the assembled-verifier step; this chip pins the
//! per-batch DEEP-quotient arithmetic, the analog of `fri_fold_chip` pinning one
//! fold step.)
//!
//! Run: `cargo test -p zkpvm --test deep_quotient_chip -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, mobile_config};
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::{ComplexConjugate, FieldExpOps};
use stwo::core::pcs::quotients::{
    ColumnSampleBatch, PointSample, accumulate_row_quotients, denominator_inverses,
    quotient_constants,
};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::COMPOSITION_LOG_SPLIT;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// Columns from the inner proof's main tree the chip forms a DEEP quotient over.
const N_DQ_COLS: usize = 3;

// ── A representative inner proof (a·b == out, a·a⁻¹ == 1) ──────────────────

#[derive(Clone)]
struct InnerQm31Eval {
    log_n_rows: u32,
}
impl FrameworkEval for InnerQm31Eval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let a: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let b: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let out: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let inv: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let a = E::combine_ef(a);
        let b = E::combine_ef(b);
        let out = E::combine_ef(out);
        let inv = E::combine_ef(inv);
        eval.add_constraint(out - a.clone() * b);
        eval.add_constraint(a * inv - E::EF::one());
        eval
    }
}

const INNER_LOG: u32 = 5;
const INNER_MAIN_COLS: usize = 16;
const N_COMPOSITION_COLS: usize = 8;

fn inner_trace() -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << INNER_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..INNER_MAIN_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let a = SecureField::from_m31_array([
            BaseField::from(row as u32 + 1),
            BaseField::from(row as u32 + 7),
            BaseField::from(row as u32 + 13),
            BaseField::from(row as u32 + 23),
        ]);
        let b = SecureField::from_m31_array([
            BaseField::from(row as u32 + 2),
            BaseField::from(row as u32 + 3),
            BaseField::from(row as u32 + 5),
            BaseField::from(row as u32 + 11),
        ]);
        let out = a * b;
        let inv = a.inverse();
        let vals: Vec<BaseField> = a
            .to_m31_array()
            .into_iter()
            .chain(b.to_m31_array())
            .chain(out.to_m31_array())
            .chain(inv.to_m31_array())
            .collect();
        for (c, v) in vals.into_iter().enumerate() {
            cols[c].set(row, v);
        }
    }
    let domain = CanonicCoset::new(INNER_LOG).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

struct InnerProof {
    component: FrameworkComponent<InnerQm31Eval>,
    proof: stwo::core::proof::StarkProof<P2MerkleHasher>,
}

fn prove_inner(config: PcsConfig) -> InnerProof {
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(INNER_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(inner_trace());
    tb.commit(channel);
    let component = FrameworkComponent::<InnerQm31Eval>::new(
        &mut TraceLocationAllocator::default(),
        InnerQm31Eval {
            log_n_rows: INNER_LOG,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .expect("prove the inner AIR");
    InnerProof { component, proof }
}

// ── Extract real OODS geometry + DEEP coeff, then build a real oracle ──────

struct DeepData {
    oods_y: SecureField,                   // the OODS point's y (QM31)
    alpha: SecureField,                    // the DEEP random_coeff
    sampled: [SecureField; N_DQ_COLS],     // the columns' OODS sampled values
    queried: [BaseField; N_DQ_COLS],       // representative trace query openings
    domain_y: BaseField,                   // a real lifting-domain point's y
    denom: stwo::core::fields::cm31::CM31, // denominator_inverses(oods, domain)[0]
    oracle: SecureField,                   // stwo's accumulate_row_quotients output
}

/// Replicate the verifier transcript through the DEEP `random_coeff` draw, then
/// build a real one-batch DEEP quotient over `N_DQ_COLS` main columns using
/// stwo's own `accumulate_row_quotients` as the oracle.
fn extract(inner: &InnerProof, config: PcsConfig) -> DeepData {
    let component = &inner.component;
    let proof = &inner.proof;

    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], channel); // preprocessed (empty)
    vs.commit(proof.commitments[1], &sizes[1], channel); // main

    let components = Components {
        components: vec![component as &dyn Component],
        n_preprocessed_columns: 0,
    };
    let split = components.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split + config.fri_config.log_blowup_factor).unwrap();
    let mlbd = lifting_log_size - config.fri_config.log_blowup_factor;

    let _composition_coeff = channel.draw_secure_felt();
    vs.commit(
        *proof.commitments.last().unwrap(),
        &[mlbd; N_COMPOSITION_COLS],
        channel,
    ); // composition
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // verify_values: mix the sampled values, then draw the DEEP random_coeff.
    channel.mix_felts(&proof.sampled_values.clone().flatten_cols());
    let alpha = channel.draw_secure_felt();

    // The columns' real OODS samples (main tree, first N_DQ_COLS columns).
    let sampled: [SecureField; N_DQ_COLS] = std::array::from_fn(|i| proof.sampled_values[1][i][0]);

    // A real lifting-domain query point + representative trace openings. (The
    // assembled verifier wires the drawn query positions + the proof's
    // queried_values; here any valid lifting-domain point + openings exercise the
    // arithmetic, with stwo's own accumulate_row_quotients as the oracle.)
    let lifting_domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let domain_point = lifting_domain.at(bit_reverse_index(1, lifting_log_size));
    let queried: [BaseField; N_DQ_COLS] =
        std::array::from_fn(|i| BaseField::from((i as u32) * 7 + 3));

    // Build the single OODS-point batch with α^i powers (the fri_answers shape).
    let mut pow = SecureField::one();
    let per_col: Vec<Vec<(PointSample, SecureField)>> = (0..N_DQ_COLS)
        .map(|i| {
            let entry = vec![(
                PointSample {
                    point: oods_point,
                    value: sampled[i],
                },
                pow,
            )];
            pow *= alpha;
            entry
        })
        .collect();
    let refs: Vec<&Vec<(PointSample, SecureField)>> = per_col.iter().collect();
    let sample_batches = ColumnSampleBatch::new_vec(&refs);
    let qc = quotient_constants(&sample_batches);
    let oracle = accumulate_row_quotients(&sample_batches, &queried, &qc, domain_point);
    let denom = denominator_inverses(&[oods_point], domain_point)[0];

    DeepData {
        oods_y: oods_point.y,
        alpha,
        sampled,
        queried,
        domain_y: domain_point.y,
        denom,
        oracle,
    }
}

// ── The DEEP-quotient chip AIR ─────────────────────────────────────────────

/// Per-column QM31 groups (4 M31 each) + shared, in evaluate/fill order:
/// shared: alpha, oods_y, [domain_y(1), d0(1), d1(1)] packed as one QM31-ish
/// triple is awkward, so domain_y/denom are read as plain M31 masks. Per column
/// i: value, alphapow, m1, m2, a, b, c, qc, ady (9 QM31). Plus result (1 QM31).
const QM31_W: usize = 4;
/// Shared QM31 columns: alpha, oods_y.
const SHARED_QM31: usize = 2;
/// Shared M31 columns: domain_y, d0, d1.
const SHARED_M31: usize = 3;
/// Per-column QM31 groups: value, alphapow, m1, m2, a, b, c, qc, ady.
const PER_COL_QM31: usize = 9;
/// Per-column M31 columns: queried.
const PER_COL_M31: usize = 1;
const N_COLS: usize =
    SHARED_QM31 * QM31_W + SHARED_M31 + N_DQ_COLS * (PER_COL_QM31 * QM31_W + PER_COL_M31) + QM31_W; // result

#[derive(Clone)]
struct DeepQuotientEval {
    log_n_rows: u32,
    oracle: SecureField,
}

impl FrameworkEval for DeepQuotientEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let read_q =
            |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };
        let ef = E::combine_ef;
        let zero = E::F::zero();

        // `conj(v) - v` for a QM31 v = [v0,v1,v2,v3] is [0,0,-2v2,-2v3].
        let conj_minus_self = |v: &[E::F; 4]| -> E::EF {
            E::combine_ef([
                zero.clone(),
                zero.clone(),
                zero.clone() - v[2].clone() - v[2].clone(),
                zero.clone() - v[3].clone() - v[3].clone(),
            ])
        };

        let alpha = read_q(&mut eval);
        let oods_y = read_q(&mut eval);
        let domain_y = eval.next_trace_mask();
        let d0 = eval.next_trace_mask();
        let d1 = eval.next_trace_mask();

        let alpha_ef = ef(alpha);
        let raw_c = conj_minus_self(&oods_y); // shared across columns
        let oods_y_ef = ef(oods_y);
        let domain_y_ef =
            E::combine_ef([domain_y.clone(), zero.clone(), zero.clone(), zero.clone()]);

        let mut numerator = E::EF::zero();
        let mut prev_pow: Option<E::EF> = None;

        for _ in 0..N_DQ_COLS {
            let value = read_q(&mut eval);
            let queried = eval.next_trace_mask();
            let alphapow = read_q(&mut eval);
            let m1 = read_q(&mut eval); // value · raw_c
            let m2 = read_q(&mut eval); // raw_a · oods_y
            let a = read_q(&mut eval); // alphapow · raw_a
            let b = read_q(&mut eval); // alphapow · raw_b
            let c = read_q(&mut eval); // alphapow · raw_c
            let qc = read_q(&mut eval); // queried · c
            let ady = read_q(&mut eval); // a · domain_y

            let raw_a = conj_minus_self(&value);
            let alphapow_ef = ef(alphapow);

            // α-power chain: αpow₀ = 1, αpowᵢ = αpowᵢ₋₁ · α.
            match &prev_pow {
                None => eval.add_constraint(alphapow_ef.clone() - E::EF::one()),
                Some(prev) => {
                    eval.add_constraint(alphapow_ef.clone() - prev.clone() * alpha_ef.clone())
                }
            }
            prev_pow = Some(alphapow_ef.clone());

            // raw_b = value·raw_c − raw_a·oods_y (witnessed products m1, m2).
            let m1_ef = ef(m1);
            let m2_ef = ef(m2);
            eval.add_constraint(m1_ef.clone() - ef(value) * raw_c.clone());
            eval.add_constraint(m2_ef.clone() - raw_a.clone() * oods_y_ef.clone());
            let raw_b = m1_ef - m2_ef;

            // (a,b,c) = αpowᵢ · (raw_a, raw_b, raw_c).
            let a_ef = ef(a);
            let b_ef = ef(b);
            let c_ef = ef(c);
            eval.add_constraint(a_ef.clone() - alphapow_ef.clone() * raw_a);
            eval.add_constraint(b_ef.clone() - alphapow_ef.clone() * raw_b);
            eval.add_constraint(c_ef.clone() - alphapow_ef * raw_c.clone());

            // qc = queried·c, ady = a·domain_y (queried/domain_y are base field).
            let queried_ef = E::combine_ef([queried, zero.clone(), zero.clone(), zero.clone()]);
            let qc_ef = ef(qc);
            let ady_ef = ef(ady);
            eval.add_constraint(qc_ef.clone() - c_ef * queried_ef);
            eval.add_constraint(ady_ef.clone() - a_ef * domain_y_ef.clone());

            // term = queried·c − (a·domain_y + b).
            numerator += qc_ef - ady_ef - b_ef;
        }

        // result = numerator · denom, denom = CM31(d0,d1) embedded as [d0,d1,0,0].
        let result = read_q(&mut eval);
        let result_ef = ef(result);
        let denom_ef = E::combine_ef([d0, d1, zero.clone(), zero]);
        eval.add_constraint(result_ef.clone() - numerator * denom_ef);

        // The DEEP quotient must equal stwo's accumulate_row_quotients output.
        eval.add_constraint(result_ef - E::EF::from(self.oracle));

        eval
    }
}

// ── Host trace fill (same order as evaluate reads) ─────────────────────────

fn push_q(row: &mut Vec<BaseField>, q: SecureField) {
    row.extend(q.to_m31_array());
}

fn row_values(d: &DeepData) -> Vec<BaseField> {
    let mut row = Vec::with_capacity(N_COLS);
    push_q(&mut row, d.alpha);
    push_q(&mut row, d.oods_y); // already QM31
    row.push(d.domain_y);
    row.push(d.denom.0);
    row.push(d.denom.1);

    let conj_minus_self = |v: SecureField| -> SecureField { v.complex_conjugate() - v };
    let raw_c = conj_minus_self(d.oods_y);
    let mut pow = SecureField::one();
    let mut numerator = SecureField::zero();
    for i in 0..N_DQ_COLS {
        let value = d.sampled[i];
        let raw_a = conj_minus_self(value);
        let m1 = value * raw_c;
        let m2 = raw_a * d.oods_y;
        let raw_b = m1 - m2;
        let a = pow * raw_a;
        let b = pow * raw_b;
        let c = pow * raw_c;
        let queried = SecureField::from(d.queried[i]);
        let qc = c * queried;
        let ady = a * SecureField::from(d.domain_y);

        push_q(&mut row, value);
        row.push(d.queried[i]);
        push_q(&mut row, pow);
        push_q(&mut row, m1);
        push_q(&mut row, m2);
        push_q(&mut row, a);
        push_q(&mut row, b);
        push_q(&mut row, c);
        push_q(&mut row, qc);
        push_q(&mut row, ady);

        numerator += qc - ady - b;
        pow *= d.alpha;
    }
    let result = numerator.mul_cm31(d.denom);
    push_q(&mut row, result);

    debug_assert_eq!(row.len(), N_COLS);
    row
}

const TRACE_LOG: u32 = 5;

fn gen_trace(
    d: &DeepData,
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << TRACE_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    let row = row_values(d);
    // Fill EVERY row identically: the oracle-match constraint is not satisfied by
    // zero padding, so all rows carry the same valid quotient.
    for r in 0..n {
        for (c, v) in row.iter().enumerate() {
            cols[c].set(r, *v);
        }
    }
    if let Some(c) = tamper_col {
        let orig = cols[c].at(0);
        cols[c].set(0, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(TRACE_LOG).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

fn prove_and_verify(d: &DeepData, tamper_col: Option<usize>) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(d, tamper_col);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(TRACE_LOG + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace);
    tb.commit(channel);
    let component = FrameworkComponent::<DeepQuotientEval>::new(
        &mut TraceLocationAllocator::default(),
        DeepQuotientEval {
            log_n_rows: TRACE_LOG,
            oracle: d.oracle,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify_inner(&component, vch, &mut vs, proof)
}

fn verify_inner(
    component: &FrameworkComponent<DeepQuotientEval>,
    vch: &mut Poseidon2M31Channel,
    vs: &mut CommitmentSchemeVerifier<P2MerkleChannel>,
    proof: stwo::core::proof::StarkProof<P2MerkleHasher>,
) -> Result<(), String> {
    stwo::core::verifier::verify(&[component as &dyn Component], vch, vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// FAST: the real DEEP-quotient trace satisfies the AIR (drives AssertEvaluator).
#[test]
fn deep_quotient_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let config = mobile_config();
    let inner = prove_inner(config);
    let d = extract(&inner, config);
    let trace = gen_trace(&d, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = DeepQuotientEval {
        log_n_rows: TRACE_LOG,
        oracle: d.oracle,
    };
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "deep_quotient_air_satisfied: in-AIR DEEP quotient over {N_DQ_COLS} columns \
         matches stwo accumulate_row_quotients (oracle {:?}); trace satisfies the AIR.",
        d.oracle
    );
}

/// THE GATE: the in-AIR DEEP quotient matches stwo's `accumulate_row_quotients`
/// on real OODS data, proves+verifies through the lifted Poseidon2-M31 protocol,
/// and a perturbed queried value is rejected.
#[test]
fn deep_quotient_gate() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let d = extract(&inner, config);

    prove_and_verify(&d, None).expect("honest DEEP quotient must prove+verify");

    // Perturb the first column's committed queried value ⇒ the recomputed
    // quotient diverges from the oracle ⇒ rejected. queried[0] sits right after
    // the first column's value QM31: shared (2*4 + 3) + value(4).
    let queried0_col = SHARED_QM31 * QM31_W + SHARED_M31 + QM31_W;
    assert!(
        prove_and_verify(&d, Some(queried0_col)).is_err(),
        "a perturbed queried value must be rejected"
    );

    eprintln!(
        "deep_quotient_gate GREEN: a real inner proof's per-batch DEEP quotient \
         (real OODS point + DEEP coeff, oracle = stwo accumulate_row_quotients) is \
         re-evaluated in-AIR and proves+verifies through the lifted Poseidon2-M31 \
         protocol; a perturbed queried value is rejected."
    );
}
