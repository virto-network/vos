//! Recursion build P3 — the **FriFoldChip**: one FRI fold step in-AIR.
//!
//! The in-AIR FRI verifier folds each query's sibling pair, per layer, with the
//! layer's `fold_alpha` (drawn by the ChannelChip). stwo's fold — both the
//! first-layer circle→line fold (`fold_circle_into_line`) and every inner-layer
//! line fold (`fold_line`) — is one `ibutterfly` + an alpha combine, which is the
//! single closed form
//!
//! ```text
//!   folded = (f_x + f_neg_x) + alpha · ((f_x − f_neg_x) · itwid)
//! ```
//!
//! where `f_x, f_neg_x, alpha, folded` are QM31 and `itwid` is an M31 twiddle —
//! `x.inverse()` (x = the line-domain x-coordinate) for a line fold, or
//! `p.y.inverse()` (p = the circle-domain point) for the first circle fold. Only
//! the twiddle source differs, so ONE chip arithmetizes both.
//!
//! Arithmetized as QM31-over-4×M31 (the `qm31_constraints.rs` idiom): witness the
//! scaled difference and the alpha product and assert equality — all degree ≤ 2:
//!
//! ```text
//!   scaled[k] == (f_x[k] − f_neg_x[k]) · itwid          (k in 0..4, degree 2)
//!   prod      == alpha · scaled                          (QM31 mul, degree 2)
//!   folded    == (f_x + f_neg_x) + prod                  (degree 1)
//! ```
//!
//! GREEN GATE: real fold steps — computed by stwo's own `fold_line` /
//! `fold_circle_into_line` on real evaluations — are reproduced in-AIR, prove +
//! verify through the lifted Poseidon2-M31 protocol, and a perturbed fold output
//! is rejected. Row-local (no cross-row), so padding rows are the zero fold.
//!
//! Run: `cargo test -p zkpvm --test fri_fold_chip -- --nocapture`

mod recursion_common;

use num_traits::Zero;
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::circle::Coset;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{FOLD_STEP, fold_circle_into_line, fold_line};
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, ColumnOps, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// Columns per row: f_x[4], f_neg_x[4], alpha[4], itwid[1], scaled[4], prod[4],
/// folded[4].
const N_COLS: usize = 4 + 4 + 4 + 1 + 4 + 4 + 4;

#[derive(Clone)]
struct FriFoldEval {
    log_n_rows: u32,
}

impl FrameworkEval for FriFoldEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let f_x: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let f_neg_x: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let alpha: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let itwid = eval.next_trace_mask();
        let scaled: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let prod: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
        let folded: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());

        // scaled == (f_x − f_neg_x) · itwid, per coordinate (the ibutterfly's
        // `(v0 − v1) · itwid`).
        for k in 0..4 {
            eval.add_constraint(
                scaled[k].clone() - (f_x[k].clone() - f_neg_x[k].clone()) * itwid.clone(),
            );
        }

        // prod == alpha · scaled (QM31 mul).
        let alpha_ef = E::combine_ef(alpha);
        let scaled_ef = E::combine_ef(scaled);
        let prod_ef = E::combine_ef(prod.clone());
        eval.add_constraint(prod_ef.clone() - alpha_ef * scaled_ef);

        // folded == (f_x + f_neg_x) + prod.
        let fx_ef = E::combine_ef(f_x);
        let fnx_ef = E::combine_ef(f_neg_x);
        let folded_ef = E::combine_ef(folded);
        eval.add_constraint(folded_ef - (fx_ef + fnx_ef + prod_ef));

        eval
    }
}

// ── Real fold data (oracle = stwo's own fold functions) ────────────────────

/// One fold step's column values, in the order [`FriFoldEval::evaluate`] reads
/// them. Cross-checks the closed form against the oracle `folded`.
fn fold_row(
    f_x: SecureField,
    f_neg_x: SecureField,
    alpha: SecureField,
    itwid: BaseField,
    oracle_folded: SecureField,
) -> Vec<BaseField> {
    let scaled = (f_x - f_neg_x) * itwid;
    let prod = alpha * scaled;
    let folded = (f_x + f_neg_x) + prod;
    assert_eq!(
        folded, oracle_folded,
        "closed-form fold must match stwo's fold output"
    );
    let mut row = Vec::with_capacity(N_COLS);
    row.extend(f_x.to_m31_array());
    row.extend(f_neg_x.to_m31_array());
    row.extend(alpha.to_m31_array());
    row.push(itwid);
    row.extend(scaled.to_m31_array());
    row.extend(prod.to_m31_array());
    row.extend(folded.to_m31_array());
    debug_assert_eq!(row.len(), N_COLS);
    row
}

fn sf(x: u32) -> SecureField {
    SecureField::from(BaseField::from(x))
}

/// Inner-layer line folds: a real degree-8 line polynomial, evaluated over a
/// line domain and folded by stwo's `fold_line`. Each sibling pair → one row.
fn line_fold_rows(alpha: SecureField) -> Vec<Vec<BaseField>> {
    const DEGREE: usize = 8;
    let even = [1u32, 2, 1, 3].map(sf);
    let odd = [3u32, 5, 4, 1].map(sf);
    let poly = LinePoly::new([even.to_vec(), odd.to_vec()].concat());
    let domain = LineDomain::new(Coset::half_odds(DEGREE.ilog2()));
    let mut values: Vec<SecureField> = domain
        .iter()
        .map(|p| poly.eval_at_point(p.into()))
        .collect();
    CpuBackend::bit_reverse_column(&mut values);

    let (_drp_domain, drp_evals) = fold_line(&values, domain, alpha);
    (0..DEGREE / 2)
        .map(|i| {
            let f_x = values[2 * i];
            let f_neg_x = values[2 * i + 1];
            let x = domain.at(bit_reverse_index(i << FOLD_STEP, domain.log_size()));
            fold_row(f_x, f_neg_x, alpha, x.inverse(), drp_evals[i])
        })
        .collect()
}

/// First-layer circle→line fold: real circle-domain evaluations folded by stwo's
/// `fold_circle_into_line` (twiddle = `p.y.inverse()`). Each pair → one row.
fn circle_fold_rows(alpha: SecureField) -> Vec<Vec<BaseField>> {
    const LOG: u32 = 4;
    let src_domain = CanonicCoset::new(LOG).circle_domain();
    let src: Vec<SecureField> = (0..src_domain.size())
        .map(|i| sf((i as u32) * 7 + 1))
        .collect();
    let folded = fold_circle_into_line(&src, src_domain, alpha);
    (0..src.len() / 2)
        .map(|i| {
            let f_p = src[2 * i];
            let f_neg_p = src[2 * i + 1];
            let p = src_domain.at(bit_reverse_index(i << 1, src_domain.log_size()));
            fold_row(f_p, f_neg_p, alpha, p.y.inverse(), folded[i])
        })
        .collect()
}

/// All real fold rows (line + circle) for a representative alpha.
fn all_fold_rows() -> Vec<Vec<BaseField>> {
    let alpha = sf(19283); // representative fold_alpha (drawn by the channel in-context)
    let mut rows = line_fold_rows(alpha);
    rows.extend(circle_fold_rows(alpha));
    rows
}

fn gen_trace(
    rows: &[Vec<BaseField>],
    folded_tamper: Option<usize>,
) -> (
    Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    u32,
) {
    let log_size = (rows.len() as u32)
        .next_power_of_two()
        .trailing_zeros()
        .max(5);
    let n = 1usize << log_size;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for (row, vals) in rows.iter().enumerate() {
        for (c, v) in vals.iter().enumerate() {
            cols[c].set(row, *v);
        }
    }
    // Perturb a committed fold OUTPUT (folded[0], column 4+4+4+1+4+4 = 21).
    if let Some(row) = folded_tamper {
        let orig = cols[21].at(row);
        cols[21].set(row, orig + BaseField::from(1u32));
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = cols
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect();
    (trace, log_size)
}

fn prove_and_verify(folded_tamper: Option<usize>) -> Result<(), String> {
    let config = mobile_config();
    let rows = all_fold_rows();
    let (trace, log_size) = gen_trace(&rows, folded_tamper);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
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

    let component = FrameworkComponent::<FriFoldEval>::new(
        &mut TraceLocationAllocator::default(),
        FriFoldEval {
            log_n_rows: log_size,
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
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// FAST: the real fold rows satisfy the AIR row-by-row (drives `AssertEvaluator`).
#[test]
fn fri_fold_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let rows = all_fold_rows();
    let (trace, log_size) = gen_trace(&rows, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = FriFoldEval {
        log_n_rows: log_size,
    };
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "fri_fold_air_satisfied: {} real fold steps (line + circle, oracle = stwo \
         fold_line/fold_circle_into_line) satisfy the AIR.",
        rows.len()
    );
}

/// THE GATE: real FRI fold steps reproduce in-AIR, prove+verify through the
/// lifted Poseidon2-M31 protocol, and a perturbed fold output is rejected.
#[test]
fn fri_fold_gate() {
    prove_and_verify(None).expect("honest FRI folds must prove+verify");
    assert!(
        prove_and_verify(Some(0)).is_err(),
        "a perturbed fold output must be rejected"
    );
    eprintln!(
        "fri_fold_gate GREEN: real FRI fold steps (line + circle, cross-checked \
         against stwo's fold_line/fold_circle_into_line) prove+verify in-AIR through \
         the lifted Poseidon2-M31 protocol; a perturbed fold output is rejected."
    );
}
