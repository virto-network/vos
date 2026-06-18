//! Recursion build P4.1 — **GATE 2: the cross-layer FRI fold CHAIN in-AIR.**
//!
//! `fri_fold_chip.rs` folds ONE sibling pair; `fri_twiddle_chip.rs` derives ONE
//! layer's twiddle from the (bound) query index. This gate chains them across ALL
//! FRI layers of a real low-degree instance, exactly as the verifier's FRI
//! decommit does (`core/fri.rs:218-291`):
//!
//!   * the query index `q` halves each layer (`Queries::fold`, `queries.rs:53` —
//!     here `q >> layer` since `fold_step = 1`);
//!   * the first layer is a circle→line fold (`fold_circle_into_line`,
//!     twiddle `p.y.inverse()`), every inner layer a line fold (`fold_line`,
//!     twiddle `x.inverse()`); both reduce to the one closed form
//!     `folded = (f_x+f_neg_x) + alpha·((f_x−f_neg_x)·twid)` (`fri_fold_chip.rs`);
//!   * each layer's `folded` (at output index `q>>(layer+1)`) feeds the NEXT
//!     layer's queried eval — a bit-driven select, since `q>>(layer+1)` is the
//!     even or odd member of the next layer's sibling pair (`subset_start =
//!     (q>>1)<<1`, `fri.rs:611-614`);
//!   * every layer's twiddle is DERIVED in-AIR from `q` via the
//!     `fri_twiddle_chip.rs` conditional-point-add gadget over THAT layer's coset
//!     (no free twiddle column) — line layers take the point's `x`, the first
//!     circle layer takes its `y` (GAP 1, de-risked 2026-06-18);
//!   * the surviving query eval is checked against the last-layer polynomial
//!     (`decommit_last_layer`, `fri.rs:282-288`) — `eval == c0 + c1·x` for the
//!     degree-1 last layer (the `LinePoly::eval_at_point` Horner fold,
//!     `line.rs:138`, GAP 3).
//!
//! The whole chain rides ONE uniform `FrameworkEval`, one row per query, all
//! constraints degree ≤ 2. Every host value is cross-checked against stwo's own
//! `fold_circle_into_line` / `fold_line` / domain-point oracle before it enters
//! the trace, so the in-AIR fold chain provably reproduces the verifier's.
//!
//! GREEN GATE: a real multi-layer FRI fold chain (real low-degree poly, real
//! drawn query indices, stwo fold oracles per layer, real last-layer poly)
//! reproduces in-AIR, proves+verifies through the lifted Poseidon2-M31 protocol,
//! and a perturbed fold output is rejected. (The end-to-end coupling — first-layer
//! evals from `fri_answers`, sibling indices from the proof's `fri_witness` — is
//! the assembled-verifier step, GATE 4; this gate pins the fold-chain mechanism,
//! the analog of `fri_fold_chip` pinning one fold step.)
//!
//! Run: `cargo test -p zkpvm --test fri_fold_chain -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{fold_circle_into_line, fold_line};
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::verify;
use stwo::prover::backend::cpu::CpuCirclePoly;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

// ── FRI shape: circle domain log 6, blowup 4, fold to a degree-1 last layer. ──
const LOG0: u32 = 6; // first-layer (circle) domain log size
const D: u32 = 4; // circle poly degree bound (2^D coeffs) = LOG0 - log_blowup
const N_FOLDS: usize = 3; // 1 circle + 2 line folds (6→5→4→3)
const LAST_LOG: u32 = 3; // last-layer line domain log size = N_FOLDS folds down from LOG0
const N_QUERIES: usize = 24; // query indices folded down the chain (one per row)

// ── The per-layer coset geometry the twiddle gadget is parameterised by. ──────
/// `domain_point(idx) = initial + Σ_{idx_k=1} q_pts[k]` where
/// `q_pts[k] = (step_size·2^{L-1-k}).to_point()` — the point bit `k` selects
/// (`fri_twiddle_chip.rs`). One per fold layer.
#[derive(Clone)]
struct CosetConsts {
    initial: CirclePoint<BaseField>,
    q_pts: Vec<CirclePoint<BaseField>>, // length L = the layer's log size
}

fn coset_consts(domain: &LineDomain) -> CosetConsts {
    let coset = domain.coset();
    let l = domain.log_size();
    let initial = coset.initial_index.to_point();
    let q_pts = (0..l)
        .map(|k| (coset.step_size * (1usize << (l - 1 - k))).to_point())
        .collect();
    CosetConsts { initial, q_pts }
}

/// Host conditional-point-add chain: returns the witnessed point after each step
/// (the values the AIR's [`point_chain`] reads). `bits[k] ∈ {0,1}` selects
/// `pt ← pt + q_pts[k]`. The final point is `domain.at(bit_reverse(idx, L))`,
/// `idx = Σ bits[k]·2^k`.
fn point_chain_host(consts: &CosetConsts, bits: &[u32]) -> Vec<CirclePoint<BaseField>> {
    let mut pt = consts.initial;
    let mut out = Vec::with_capacity(bits.len());
    for (k, &b) in bits.iter().enumerate() {
        if b == 1 {
            pt = pt + consts.q_pts[k];
        }
        out.push(pt);
        let _ = k;
    }
    out
}

/// AIR conditional-point-add chain: reads `bits.len()` witnessed points and binds
/// each to `pt_k = bits[k] ? pt_{k-1} + q_pts[k] : pt_{k-1}` (degree 2). Returns
/// the final `(x, y)`. The `bits` are the (already boolean-constrained, q-bound)
/// query bits — a leading `E::F::zero()` encodes a forced-0 LSB (subset_start).
fn point_chain<E: EvalAtRow>(eval: &mut E, consts: &CosetConsts, bits: &[E::F]) -> (E::F, E::F) {
    let mut prev_x = E::F::from(consts.initial.x);
    let mut prev_y = E::F::from(consts.initial.y);
    for (k, bit) in bits.iter().enumerate() {
        let qkx = consts.q_pts[k].x;
        let qky = consts.q_pts[k].y;
        // (prev + q_pts[k]) — degree 1 (q_pts[k] constant).
        let added_x = prev_x.clone() * qkx - prev_y.clone() * qky;
        let added_y = prev_x.clone() * qky + prev_y.clone() * qkx;
        let cur_x = eval.next_trace_mask();
        let cur_y = eval.next_trace_mask();
        eval.add_constraint(
            cur_x.clone() - (prev_x.clone() + bit.clone() * (added_x - prev_x.clone())),
        );
        eval.add_constraint(
            cur_y.clone() - (prev_y.clone() + bit.clone() * (added_y - prev_y.clone())),
        );
        prev_x = cur_x;
        prev_y = cur_y;
    }
    (prev_x, prev_y)
}

// ── The real FRI fold chain (oracle = stwo fold_circle_into_line / fold_line) ──

struct ChainData {
    /// Drawn query indices (LOG0-bit), one per row.
    queries: Vec<usize>,
    /// Layer cosets (line1 .. line_last), for the twiddle gadget.
    line1: CosetConsts,
    line2: CosetConsts,
    line3: CosetConsts,
    /// The fold alphas (real channel draws), one per fold.
    alphas: [SecureField; N_FOLDS],
    /// Full per-layer evaluations (bit-reversed), indexed by the layer's query.
    circle0: Vec<SecureField>, // log 6
    line1_evals: Vec<SecureField>, // log 5
    line2_evals: Vec<SecureField>, // log 4
    line3_evals: Vec<SecureField>, // log 3 (the last layer)
    /// Last-layer degree-1 poly coefficients (`eval_at_point(x) = c0 + c1·x`).
    c0: SecureField,
    c1: SecureField,
    /// The geometric x-coordinate the last-layer query maps to, per query.
    last_domain: LineDomain,
}

fn build_chain() -> ChainData {
    // A real low-degree circle poly evaluated on the first-layer domain.
    let circle_domain = CanonicCoset::new(LOG0).circle_domain();
    let coeffs: Vec<BaseField> = (0..(1usize << D))
        .map(|i| BaseField::from((i as u32) * 0x9e37 + 7))
        .collect();
    let poly = CpuCirclePoly::new(coeffs);
    let circle0: Vec<SecureField> = poly
        .evaluate(circle_domain)
        .values
        .into_iter()
        .map(SecureField::from)
        .collect();

    // Real fold alphas, drawn from a Poseidon2-M31 channel.
    let channel = &mut Poseidon2M31Channel::default();
    let alphas: [SecureField; N_FOLDS] = std::array::from_fn(|_| channel.draw_secure_felt());

    let line1_domain = LineDomain::new(circle_domain.half_coset);
    let line1_evals = fold_circle_into_line(&circle0, circle_domain, alphas[0]);
    let (line2_domain, line2_evals) = fold_line(&line1_evals, line1_domain, alphas[1]);
    let (line3_domain, line3_evals) = fold_line(&line2_evals, line2_domain, alphas[2]);
    assert_eq!(line3_domain.log_size(), LAST_LOG);

    // The last layer is degree-1: solve c0, c1 from two points, assert the rest.
    let x_at = |j: usize| line3_domain.at(bit_reverse_index(j, LAST_LOG));
    let (x0, x1) = (x_at(0), x_at(1));
    let c1 = (line3_evals[1] - line3_evals[0]) * (SecureField::from(x1 - x0)).inverse();
    let c0 = line3_evals[0] - c1 * SecureField::from(x0);
    for (j, &e) in line3_evals.iter().enumerate() {
        debug_assert_eq!(
            e,
            c0 + c1 * SecureField::from(x_at(j)),
            "last layer must be degree 1 (eval {j})"
        );
    }

    // Real query indices.
    let qch = &mut Poseidon2M31Channel::default();
    let mask = (1usize << LOG0) - 1;
    let mut queries = Vec::new();
    while queries.len() < N_QUERIES {
        for w in qch.draw_u32s() {
            queries.push((w as usize) & mask);
            if queries.len() == N_QUERIES {
                break;
            }
        }
    }

    ChainData {
        queries,
        line1: coset_consts(&line1_domain),
        line2: coset_consts(&line2_domain),
        line3: coset_consts(&line3_domain),
        alphas,
        circle0,
        line1_evals,
        line2_evals,
        line3_evals,
        c0,
        c1,
        last_domain: line3_domain,
    }
}

// ── Column layout (must match `row_values` ↔ `FriFoldChainEval::evaluate`) ─────
// shared:  q(1) bits[6]
// fold0(circle): f_p[4] f_neg_p[4] alpha0[4] chain0(x,y)×5 ty0(1) scaled0[4] prod0[4] folded0[4]
// fold1(line):   f_x1[4] f_neg_x1[4] alpha1[4] chain1(x,y)×5 tx1(1) scaled1[4] prod1[4] folded1[4]
// fold2(line):   f_x2[4] f_neg_x2[4] alpha2[4] chain2(x,y)×4 tx2(1) scaled2[4] prod2[4] folded2[4]
// last:          chainL(x,y)×3
const N_COLS: usize =
    (1 + 6) + (8 + 4 + 10 + 1 + 12) + (8 + 4 + 10 + 1 + 12) + (8 + 4 + 8 + 1 + 12) + 6;

#[derive(Clone)]
struct FriFoldChainEval {
    log_n_rows: u32,
    line1: CosetConsts,
    line2: CosetConsts,
    line3: CosetConsts,
    c0: SecureField,
    c1: SecureField,
}

impl FrameworkEval for FriFoldChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let zero = E::F::zero();
        let read4 = |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };

        // ── shared: q + its LOG0 boolean bits (recompose to q ⇒ binds them). ──
        let q = eval.next_trace_mask();
        let bits: [E::F; LOG0 as usize] = std::array::from_fn(|_| eval.next_trace_mask());
        let mut recompose = E::F::zero();
        let mut coeff = BaseField::one();
        for bit in &bits {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            recompose += bit.clone() * coeff;
            coeff += coeff;
        }
        eval.add_constraint(recompose - q);

        // One fold step's closed form: folded = (f_a+f_b) + alpha·((f_a−f_b)·twid).
        // `twid` is a base-field value; `scaled/prod/folded` are QM31 (witnessed).
        let fold_step = |eval: &mut E,
                         f_a: [E::F; 4],
                         f_b: [E::F; 4],
                         alpha: [E::F; 4],
                         twid: E::F|
         -> [E::F; 4] {
            let scaled = read4(eval);
            let prod = read4(eval);
            let folded = read4(eval);
            for k in 0..4 {
                eval.add_constraint(
                    scaled[k].clone() - (f_a[k].clone() - f_b[k].clone()) * twid.clone(),
                );
            }
            let prod_ef = E::combine_ef(prod.clone());
            eval.add_constraint(prod_ef.clone() - E::combine_ef(alpha) * E::combine_ef(scaled));
            eval.add_constraint(
                E::combine_ef(folded.clone()) - (E::combine_ef(f_a) + E::combine_ef(f_b) + prod_ef),
            );
            folded
        };

        // `folded == select(bit, f_x, f_neg_x)` — chains a fold's output into the
        // next layer's queried eval (the even/odd member of its sibling pair).
        let chain_select =
            |eval: &mut E, folded: &[E::F; 4], f_x: &[E::F; 4], f_neg_x: &[E::F; 4], bit: &E::F| {
                for k in 0..4 {
                    let sel = f_x[k].clone() + bit.clone() * (f_neg_x[k].clone() - f_x[k].clone());
                    eval.add_constraint(folded[k].clone() - sel);
                }
            };

        // Witnessed inverse: `t · coord == 1` ⇒ `t` is the fold twiddle.
        let inv_of = |eval: &mut E, coord: E::F| -> E::F {
            let t = eval.next_trace_mask();
            eval.add_constraint(t.clone() * coord - one.clone());
            t
        };

        // ── fold 0: circle → line. twiddle = pt.y.inverse(), pt over line1 coset
        //    at index q>>1 (bits[1..6]); pair = circle0[2·(q>>1) (+1)]. ──
        let f_p = read4(&mut eval);
        let f_neg_p = read4(&mut eval);
        let alpha0 = read4(&mut eval);
        let bits0: Vec<E::F> = bits[1..6].to_vec();
        let (_x0, y0) = point_chain(&mut eval, &self.line1, &bits0);
        let twid0 = inv_of(&mut eval, y0);
        let folded0 = fold_step(&mut eval, f_p, f_neg_p, alpha0, twid0);

        // ── fold 1: line → line. twiddle = pt.x.inverse(), pt over line1 coset at
        //    index subset_start = 2·(q>>2) (bits [0, 2,3,4,5]). ──
        let f_x1 = read4(&mut eval);
        let f_neg_x1 = read4(&mut eval);
        chain_select(&mut eval, &folded0, &f_x1, &f_neg_x1, &bits[1]);
        let alpha1 = read4(&mut eval);
        let bits1: Vec<E::F> = core::iter::once(zero.clone())
            .chain(bits[2..6].iter().cloned())
            .collect();
        let (x1, _y1) = point_chain(&mut eval, &self.line1, &bits1);
        let twid1 = inv_of(&mut eval, x1);
        let folded1 = fold_step(&mut eval, f_x1, f_neg_x1, alpha1, twid1);

        // ── fold 2: line → line (last fold). twiddle over line2 coset at index
        //    subset_start = 2·(q>>3) (bits [0, 3,4,5]). ──
        let f_x2 = read4(&mut eval);
        let f_neg_x2 = read4(&mut eval);
        chain_select(&mut eval, &folded1, &f_x2, &f_neg_x2, &bits[2]);
        let alpha2 = read4(&mut eval);
        let bits2: Vec<E::F> = core::iter::once(zero.clone())
            .chain(bits[3..6].iter().cloned())
            .collect();
        let (x2, _y2) = point_chain(&mut eval, &self.line2, &bits2);
        let twid2 = inv_of(&mut eval, x2);
        let folded2 = fold_step(&mut eval, f_x2, f_neg_x2, alpha2, twid2);

        // ── last layer: folded2 is the surviving query eval at index q>>3 on the
        //    last-layer domain. Check folded2 == c0 + c1·x_last (LinePoly Horner
        //    fold for the degree-1 last layer). x_last over line3 coset at index
        //    q>>3 (bits [3,4,5]) — the actual query point, no LSB zeroing. ──
        let bits_l: Vec<E::F> = bits[3..6].to_vec();
        let (x_last, _yl) = point_chain(&mut eval, &self.line3, &bits_l);
        let x_last_ef = E::combine_ef([x_last, zero.clone(), zero.clone(), zero.clone()]);
        let c1x = E::EF::from(self.c1) * x_last_ef;
        eval.add_constraint(E::combine_ef(folded2) - (E::EF::from(self.c0) + c1x));

        eval
    }
}

// ── Host trace fill (same order the eval reads) ───────────────────────────────

fn push4(row: &mut Vec<BaseField>, q: SecureField) {
    row.extend(q.to_m31_array());
}

/// One query's full fold-chain row. Cross-checks every fold against stwo's
/// oracle (the full-layer fold output) before committing it.
fn row_values(d: &ChainData, q: usize) -> Vec<BaseField> {
    let mut row = Vec::with_capacity(N_COLS);
    let bits: [u32; LOG0 as usize] = std::array::from_fn(|k| ((q >> k) & 1) as u32);

    // shared
    row.push(BaseField::from(q as u32));
    for b in bits {
        row.push(BaseField::from(b));
    }

    // closed-form fold + oracle cross-check.
    let fold = |f_a: SecureField,
                f_b: SecureField,
                alpha: SecureField,
                twid: BaseField,
                oracle: SecureField|
     -> (SecureField, SecureField, SecureField) {
        let scaled = (f_a - f_b) * twid;
        let prod = alpha * scaled;
        let folded = (f_a + f_b) + prod;
        debug_assert_eq!(folded, oracle, "closed-form fold must match stwo oracle");
        (scaled, prod, folded)
    };
    let push_chain = |row: &mut Vec<BaseField>, pts: &[CirclePoint<BaseField>]| {
        for p in pts {
            row.push(p.x);
            row.push(p.y);
        }
    };

    // fold 0 (circle): output index i0 = q>>1, pair {2·i0, 2·i0+1}.
    let i0 = q >> 1;
    let f_p = d.circle0[2 * i0];
    let f_neg_p = d.circle0[2 * i0 + 1];
    let pts0 = point_chain_host(&d.line1, &bits[1..6]);
    let y0 = pts0.last().unwrap().y;
    let twid0 = y0.inverse();
    let (s0, p0, folded0) = fold(f_p, f_neg_p, d.alphas[0], twid0, d.line1_evals[i0]);
    push4(&mut row, f_p);
    push4(&mut row, f_neg_p);
    push4(&mut row, d.alphas[0]);
    push_chain(&mut row, &pts0);
    row.push(twid0);
    push4(&mut row, s0);
    push4(&mut row, p0);
    push4(&mut row, folded0);

    // fold 1 (line): query i0 on line1, pair {subset=2·(q>>2), +1}, output q>>2.
    let i1 = q >> 2;
    let f_x1 = d.line1_evals[2 * i1];
    let f_neg_x1 = d.line1_evals[2 * i1 + 1];
    debug_assert_eq!(
        folded0,
        if bits[1] == 0 { f_x1 } else { f_neg_x1 },
        "fold0 output must be line1's queried eval"
    );
    let mut bits1 = vec![0u32];
    bits1.extend_from_slice(&bits[2..6]);
    let pts1 = point_chain_host(&d.line1, &bits1);
    let x1 = pts1.last().unwrap().x;
    let twid1 = x1.inverse();
    let (s1, p1, folded1) = fold(f_x1, f_neg_x1, d.alphas[1], twid1, d.line2_evals[i1]);
    push4(&mut row, f_x1);
    push4(&mut row, f_neg_x1);
    push4(&mut row, d.alphas[1]);
    push_chain(&mut row, &pts1);
    row.push(twid1);
    push4(&mut row, s1);
    push4(&mut row, p1);
    push4(&mut row, folded1);

    // fold 2 (line, last): query i1 on line2, pair {2·(q>>3), +1}, output q>>3.
    let i2 = q >> 3;
    let f_x2 = d.line2_evals[2 * i2];
    let f_neg_x2 = d.line2_evals[2 * i2 + 1];
    debug_assert_eq!(
        folded1,
        if bits[2] == 0 { f_x2 } else { f_neg_x2 },
        "fold1 output must be line2's queried eval"
    );
    let mut bits2 = vec![0u32];
    bits2.extend_from_slice(&bits[3..6]);
    let pts2 = point_chain_host(&d.line2, &bits2);
    let x2 = pts2.last().unwrap().x;
    let twid2 = x2.inverse();
    let (s2, p2, folded2) = fold(f_x2, f_neg_x2, d.alphas[2], twid2, d.line3_evals[i2]);
    push4(&mut row, f_x2);
    push4(&mut row, f_neg_x2);
    push4(&mut row, d.alphas[2]);
    push_chain(&mut row, &pts2);
    row.push(twid2);
    push4(&mut row, s2);
    push4(&mut row, p2);
    push4(&mut row, folded2);

    // last layer: folded2 == c0 + c1·x_last, x_last = last_domain.at(bitrev(q>>3)).
    let pts_l = point_chain_host(&d.line3, &bits[3..6]);
    let x_last = pts_l.last().unwrap().x;
    debug_assert_eq!(
        x_last,
        d.last_domain.at(bit_reverse_index(i2, LAST_LOG)),
        "last-layer x must be the query's domain point"
    );
    debug_assert_eq!(
        folded2,
        d.c0 + d.c1 * SecureField::from(x_last),
        "last-layer eval check (folded2 == c0 + c1·x)"
    );
    push_chain(&mut row, &pts_l);

    debug_assert_eq!(row.len(), N_COLS);
    row
}

const TRACE_LOG: u32 = 5; // 24 queries → 32 rows

fn gen_trace(
    d: &ChainData,
    tamper_col_row: Option<(usize, usize)>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << TRACE_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    // Fill every row with a real query's chain (padding rows reuse query 0, which
    // is a valid chain — the last-layer constraint is not satisfied by zeros).
    for r in 0..n {
        let q = d.queries[r % d.queries.len()];
        for (c, v) in row_values(d, q).into_iter().enumerate() {
            cols[c].set(r, v);
        }
    }
    if let Some((c, r)) = tamper_col_row {
        let orig = cols[c].at(r);
        cols[c].set(r, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(TRACE_LOG).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

fn prove_and_verify(d: &ChainData, tamper: Option<(usize, usize)>) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(d, tamper);
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

    let component = FrameworkComponent::<FriFoldChainEval>::new(
        &mut TraceLocationAllocator::default(),
        FriFoldChainEval {
            log_n_rows: TRACE_LOG,
            line1: d.line1.clone(),
            line2: d.line2.clone(),
            line3: d.line3.clone(),
            c0: d.c0,
            c1: d.c1,
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

/// FAST: the real fold-chain trace satisfies the AIR (drives AssertEvaluator;
/// also runs all the `row_values` host cross-checks vs stwo's oracle).
#[test]
fn fri_fold_chain_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let d = build_chain();
    let trace = gen_trace(&d, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = FriFoldChainEval {
        log_n_rows: TRACE_LOG,
        line1: d.line1.clone(),
        line2: d.line2.clone(),
        line3: d.line3.clone(),
        c0: d.c0,
        c1: d.c1,
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
        "fri_fold_chain_air_satisfied: {N_QUERIES} real query fold chains ({N_FOLDS} folds each, \
         twiddle derived in-AIR from q per layer, cross-layer chained, last-layer eval) satisfy \
         the AIR."
    );
}

/// THE GATE: a real FRI fold chain reproduces in-AIR across all layers, proves +
/// verifies through the lifted Poseidon2-M31 protocol, and a perturbed fold
/// output (which breaks the cross-layer chain or the last-layer check) is rejected.
#[test]
fn fri_fold_chain_gate() {
    let d = build_chain();
    prove_and_verify(&d, None).expect("honest FRI fold chain must prove+verify");

    // Perturb folded0[0] at row 0 (column = shared(7) + f_p,f_neg_p,alpha0(12) +
    // chain0(10) + ty0(1) + scaled0,prod0(8)). Breaks fold0 AND the chain_select
    // feeding fold1 ⇒ rejected.
    let folded0_col = 7 + 12 + 10 + 1 + 8;
    assert!(
        prove_and_verify(&d, Some((folded0_col, 0))).is_err(),
        "a perturbed fold output must be rejected"
    );

    eprintln!(
        "fri_fold_chain_gate GREEN: a real {N_FOLDS}-layer FRI fold chain (real low-degree poly, \
         real drawn queries, stwo fold_circle_into_line/fold_line oracles per layer, real \
         degree-1 last-layer poly) reproduces in-AIR — query indices halve, each folded feeds the \
         next layer via a bit-select, every twiddle is DERIVED from q via the conditional \
         point-add gadget over that layer's coset, and the surviving eval matches the last-layer \
         poly; proves+verifies through the lifted Poseidon2-M31 protocol; a perturbed fold is \
         rejected."
    );
}
