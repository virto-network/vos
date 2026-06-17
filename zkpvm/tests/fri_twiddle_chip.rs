//! Recursion build P4.1 — **GAP 1: the FRI fold twiddle, derived in-AIR from the
//! query index.**
//!
//! `fri_fold_chip.rs` folds one sibling pair given the twiddle `itwid` as a FREE
//! column. That is unsound for recursion: the twiddle must be bound to the
//! drawn query index, else a prover forges the fold geometry. In the real
//! verifier the twiddle is `domain.at(bit_reverse_index(q, log)).inverse()` for a
//! line layer (the x-coordinate of the coset point at the bit-reversed query
//! index, inverted) — see `core/fri.rs:760` and `core/poly/line.rs:52`. This is
//! GAP 1 from `docs/plans/recursion-p4.md`: deriving that point in-AIR from `q`.
//!
//! ## The key structural fact (what makes GAP 1 tractable)
//!
//! `Coset::at(j) = (initial_index + step_size·j).to_point()`, and `to_point` is a
//! group homomorphism from the additive `CirclePointIndex` to the circle group.
//! With `j = bit_reverse_index(q, L) = Σ_k q_k·2^{L-1-k}`,
//!
//! ```text
//!   domain_point(q) = initial + Σ_{k : q_k = 1} Q_k ,   Q_k = (step_size·2^{L-1-k}).to_point()
//! ```
//!
//! a bit-SELECTED sum of `L` FIXED coset points. Adding a CONSTANT point
//! `(qx,qy)` to `(x,y)` is `(x·qx − y·qy, x·qy + y·qx)` — degree 1 — and the
//! per-bit select `pt ← q_k ? pt+Q_k : pt` is degree 2. So the whole derivation
//! is a depth-`L` chain of degree-2 conditional point-adds + one witnessed
//! inverse — no scalar-mult circuit, no per-query constants.
//!
//! GREEN GATE: for every query index `q ∈ [0, 2^L)`, the in-AIR derivation
//! (q's bits → conditional-adds over the coset → x.inverse()) matches stwo's own
//! `domain.at(bit_reverse_index(q, L)).inverse()`; proves+verifies through the
//! lifted Poseidon2-M31 protocol; a tampered twiddle (or query bit) is rejected.
//! This de-risks GAP 1 — the twiddle is DERIVED from the bound query index, not
//! free. (The circle-fold variant uses `p.y.inverse()`; same gadget, take y.)
//!
//! Run: `cargo test -p zkpvm --test fri_twiddle_chip -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::circle::{CirclePoint, Coset};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

/// Layer log-size (the line domain has 2^L points; query indices are L bits).
const L: usize = 5;

/// Per-row columns, in evaluate/fill order:
/// q(1) · bits[L] · (pt_x, pt_y)×L · t(1).
const ROW_COLS: usize = 1 + L + 2 * L + 1;

/// The fixed coset geometry the gadget is parameterised by.
#[derive(Clone)]
struct CosetConsts {
    initial: CirclePoint<BaseField>,
    /// `Q_k = (step_size·2^{L-1-k}).to_point()` — the point bit k of q selects.
    q_pts: [CirclePoint<BaseField>; L],
}

fn coset_consts(domain: &LineDomain) -> CosetConsts {
    let coset = domain.coset();
    let initial = coset.initial_index.to_point();
    let q_pts = std::array::from_fn(|k| (coset.step_size * (1usize << (L - 1 - k))).to_point());
    CosetConsts { initial, q_pts }
}

#[derive(Clone)]
struct TwiddleEval {
    log_n_rows: u32,
    consts: CosetConsts,
}

impl FrameworkEval for TwiddleEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();

        let q = eval.next_trace_mask();
        let bits: [E::F; L] = std::array::from_fn(|_| eval.next_trace_mask());
        let pts: [(E::F, E::F); L] =
            std::array::from_fn(|_| (eval.next_trace_mask(), eval.next_trace_mask()));
        let t = eval.next_trace_mask();

        // bits are boolean and recompose to q (binds the gadget to the query index).
        let mut recompose = E::F::zero();
        let mut coeff = BaseField::one();
        for bit in &bits {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            recompose += bit.clone() * coeff;
            coeff += coeff;
        }
        eval.add_constraint(recompose - q);

        // Conditional point-add chain: ptₖ = q_k ? ptₖ₋₁ + Q_k : ptₖ₋₁, pt₀ = initial.
        let mut prev_x = E::F::from(self.consts.initial.x);
        let mut prev_y = E::F::from(self.consts.initial.y);
        for k in 0..L {
            let qkx = self.consts.q_pts[k].x;
            let qky = self.consts.q_pts[k].y;
            // (prev + Q_k) — degree 1 (Q_k constant).
            let added_x = prev_x.clone() * qkx - prev_y.clone() * qky;
            let added_y = prev_x.clone() * qky + prev_y.clone() * qkx;
            let (cur_x, cur_y) = (pts[k].0.clone(), pts[k].1.clone());
            // select(bit, added, prev) — degree 2.
            eval.add_constraint(
                cur_x.clone() - (prev_x.clone() + bits[k].clone() * (added_x - prev_x.clone())),
            );
            eval.add_constraint(
                cur_y.clone() - (prev_y.clone() + bits[k].clone() * (added_y - prev_y.clone())),
            );
            prev_x = cur_x;
            prev_y = cur_y;
        }

        // The line-fold twiddle is the inverse of the final point's x-coordinate.
        eval.add_constraint(t * prev_x - one);

        eval
    }
}

// ── Host: the oracle (stwo domain.at) + the gadget's witnessed point chain ──

fn domain() -> LineDomain {
    LineDomain::new(Coset::half_odds(L as u32))
}

/// stwo's own twiddle for query index `q`: `domain.at(bit_reverse(q)).inverse()`.
fn oracle_twiddle(domain: &LineDomain, q: usize) -> BaseField {
    domain.at(bit_reverse_index(q, L as u32)).inverse()
}

/// One row's columns: q, its L bits, the witnessed conditional-add point chain,
/// and the derived twiddle. Cross-checks the chain against stwo's domain point.
fn row_values(consts: &CosetConsts, domain: &LineDomain, q: usize) -> Vec<BaseField> {
    let mut row = Vec::with_capacity(ROW_COLS);
    row.push(BaseField::from(q as u32));

    let bits: [u32; L] = std::array::from_fn(|k| ((q >> k) & 1) as u32);
    for b in bits {
        row.push(BaseField::from(b));
    }

    let mut pt = consts.initial;
    let mut pts = Vec::with_capacity(L);
    for k in 0..L {
        if bits[k] == 1 {
            pt = pt + consts.q_pts[k];
        }
        pts.push(pt);
    }
    // The derived point must be the coset point at the bit-reversed index.
    let j = bit_reverse_index(q, L as u32);
    debug_assert_eq!(
        pt.x,
        domain.at(j),
        "conditional-add chain must reproduce domain.at(bit_reverse(q)).x"
    );
    for p in &pts {
        row.push(p.x);
        row.push(p.y);
    }

    let t = pt.x.inverse();
    debug_assert_eq!(
        t,
        oracle_twiddle(domain, q),
        "twiddle must match the oracle"
    );
    row.push(t);

    debug_assert_eq!(row.len(), ROW_COLS);
    row
}

fn gen_trace(
    consts: &CosetConsts,
    domain: &LineDomain,
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << L; // one query index per row, the full domain
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..ROW_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for q in 0..n {
        for (c, v) in row_values(consts, domain, q).into_iter().enumerate() {
            cols[c].set(q, v);
        }
    }
    if let Some(c) = tamper_col {
        let orig = cols[c].at(1);
        cols[c].set(1, orig + BaseField::one());
    }
    let circle_domain = stwo::core::poly::circle::CanonicCoset::new(L as u32).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(circle_domain, col))
        .collect()
}

fn prove_and_verify(tamper_col: Option<usize>) -> Result<(), String> {
    use stwo::core::poly::circle::CanonicCoset;
    let config = mobile_config();
    let domain = domain();
    let consts = coset_consts(&domain);
    let trace = gen_trace(&consts, &domain, tamper_col);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(L as u32 + 1 + config.fri_config.log_blowup_factor)
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

    let component = FrameworkComponent::<TwiddleEval>::new(
        &mut TraceLocationAllocator::default(),
        TwiddleEval {
            log_n_rows: L as u32,
            consts,
        },
        SecureField::default(),
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

/// FAST: the derived-twiddle trace satisfies the AIR for every query index
/// (drives AssertEvaluator; also cross-checks against stwo via the debug_asserts
/// in `row_values`).
#[test]
fn fri_twiddle_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let domain = domain();
    let consts = coset_consts(&domain);
    let trace = gen_trace(&consts, &domain, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = TwiddleEval {
        log_n_rows: L as u32,
        consts,
    };
    assert_constraints_on_trace(
        &tv,
        L as u32,
        |e| {
            eval.evaluate(e);
        },
        SecureField::default(),
    );
    eprintln!(
        "fri_twiddle_air_satisfied: all {} query indices derive the correct line-fold \
         twiddle in-AIR (conditional point-add chain matches stwo domain.at).",
        1usize << L
    );
}

/// THE GATE: the in-AIR twiddle derivation matches stwo for every query index,
/// proves+verifies through the lifted Poseidon2-M31 protocol, and a tampered
/// query bit is rejected (the twiddle is bound to the query index, not free).
#[test]
fn fri_twiddle_gate() {
    prove_and_verify(None).expect("honest twiddle derivation must prove+verify");

    // Flip a query bit at row 1 (column 1 = bits[0]); the recompose and/or the
    // derived point diverge ⇒ rejected.
    assert!(
        prove_and_verify(Some(1)).is_err(),
        "a tampered query bit must be rejected"
    );

    eprintln!(
        "fri_twiddle_gate GREEN: the FRI fold twiddle is DERIVED in-AIR from the \
         (bound) query index via a depth-{L} conditional point-add chain over the \
         coset — matching stwo's domain.at(bit_reverse(q)).inverse() for all \
         {} indices; proves+verifies; a tampered query bit is rejected. GAP 1 \
         de-risked: no free twiddle column.",
        1usize << L
    );
}
