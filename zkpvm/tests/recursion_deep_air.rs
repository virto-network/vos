#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.3 — **step 4 standalone de-risk: the multi-batch DEEP
//! numerator with the in-AIR CM31 denominator.**
//!
//! `deep_quotient_chip.rs` (P4.1 GATE 1) already proved the per-batch DEEP
//! arithmetic in-AIR — the `(a,b,c)`-from-`(v, z.y, α^i)` derivation
//! (`complex_conjugate_line_coeffs`) + the `Σ_col (queried·c − (a·p.y + b))`
//! numerator + the `numerator · denom_inverse` product — but it took the
//! denominator `denom_inverse` as a HOST `[d0,d1,0,0]` constant. The full DEEP
//! obligation (step 4) needs the denominator DERIVED in-circuit from the batch
//! sample point `z` and the per-query domain point `p`, so a prover cannot pick it.
//!
//! This file de-risks the NEW mechanisms before the heavy log-17 integration:
//!   * **multi-batch** — several real OODS sample batches, each with its own point
//!     `z` and its own per-batch denominator, accumulated into ONE eval (the
//!     `fri_answers`/`accumulate_row_quotients` shape over the real `deep_batches`);
//!   * **the in-AIR CM31 denominator** — `line(z, z̄)(p) = (Re(zₓ)−pₓ)·Im(zᵧ) −
//!     (Re(zᵧ)−pᵧ)·Im(zₓ)`, a CM31 derived from `z`'s four CM31 coords + `p`'s two
//!     M31 coords (each CM31 product witnessed, degree 2), its inverse witnessed
//!     (`denom_inv · denom == 1`, CM31), and `numerator · denom_inv` the QM31·CM31
//!     product (`mul_cm31`);
//!   * **the bind** — the accumulated eval is asserted equal to a host oracle
//!     (the same subset, computed by the host with the validated formula), the
//!     stand-in for `first_layer_evals[qi]` the integration binds to.
//!
//! Driven off ONE REAL `prove_canonical` segment's `extract_recursion_data`
//! (`deep_batches`: the AIR-friendly `fri_answers` decomposition + `col_samples` =
//! `(v, α^i)` per column, validated in `recursion_deep_quotient.rs`). `v`/`z`/`α^i`/
//! the leaves/`p` are host inputs here; coupling `v` to the embed mask, the leaves
//! to the trace-decommit chunks, `z` to the latched OODS point, `p` to the query
//! position, and the eval to the FRI layer-0 running is the 4c integration.
//!
//! `assert_constraints_on_trace` checks only ZERO-ness, NOT the degree bound (a
//! degree-3 slip surfaces only as a FRI failure at prove), so the milestone is the
//! PROVE, not the assert.
//!
//! Run: `cargo test -p zkpvm --release --features poseidon2-channel --test \
//!     recursion_deep_air -- --ignored --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::{ComplexConjugate, FieldExpOps};
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
    assert_constraints_on_trace,
};
use zkpvm::{Proof, SideNote, extract_recursion_data};

/// How many real OODS sample batches the de-risk subset spans.
const K_BATCHES: usize = 3;
/// How many columns per batch the de-risk subset folds (capped to the batch size).
const M_COLS: usize = 4;

fn canonical_segment() -> (Proof, SideNote) {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::prove_canonical;

    let code = vec![
        Opcode::Add64 as u8,
        0x10,
        2,
        Opcode::Add64 as u8,
        0x12,
        3,
        Opcode::Add64 as u8,
        0x13,
        4,
        Opcode::Add64 as u8,
        0x14,
        5,
        Opcode::Add64 as u8,
        0x15,
        6,
        Opcode::Add64 as u8,
        0x16,
        7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        initial_memory.clone(),
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

// ── Real DEEP-batch subset extracted from one canonical segment ──────────────

/// One column term in a batch: the OODS sample `v`, the DEEP power `α^i`, and the
/// trace query opening `leaf = queried_flat[col][qi]`.
#[derive(Clone, Copy)]
struct ColTerm {
    v: SecureField,
    pow: SecureField,
    leaf: BaseField,
}

/// One batch: the sample point `z` (QM31 circle point) + its column terms.
#[derive(Clone)]
struct Batch {
    zx: SecureField,
    zy: SecureField,
    cols: Vec<ColTerm>,
}

struct DeepSubset {
    p_x: BaseField,
    p_y: BaseField,
    batches: Vec<Batch>,
    /// stwo-consistent host oracle: the accumulated DEEP eval over this subset.
    oracle: SecureField,
}

/// `line(z, z̄)(p)` as a CM31 (the conjugate-line denominator the FRI quotient
/// divides by). Matches `recursion_deep_quotient.rs`'s validated host formula.
fn denom_cm31(zx: SecureField, zy: SecureField, p_x: BaseField, p_y: BaseField) -> CM31 {
    (zx.0 - CM31::from(p_x)) * zy.1 - (zy.0 - CM31::from(p_y)) * zx.1
}

/// `(a, b, c) = α^i · (v̄−v, v·c′−a′·z.y, z̄.y−z.y)` (`complex_conjugate_line_coeffs`),
/// the host reference the in-AIR derivation must reproduce.
fn line_coeffs(
    v: SecureField,
    zy: SecureField,
    pow: SecureField,
) -> (SecureField, SecureField, SecureField) {
    let raw_a = v.complex_conjugate() - v;
    let raw_c = zy.complex_conjugate() - zy;
    let raw_b = v * raw_c - raw_a * zy;
    (pow * raw_a, pow * raw_b, pow * raw_c)
}

fn extract() -> DeepSubset {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    assert!(
        data.deep_batches.len() >= K_BATCHES,
        "segment must have ≥ {K_BATCHES} DEEP batches"
    );

    // Query 0's domain point + its trace openings (flattened across trees).
    let qi = 0usize;
    let lifting_domain = CanonicCoset::new(data.lifting_log_size).circle_domain();
    let p = lifting_domain.at(bit_reverse_index(
        data.query_positions[qi],
        data.lifting_log_size,
    ));
    let queried_flat: Vec<Vec<BaseField>> = proof.stark_proof.queried_values.clone().flatten();

    let mut batches = Vec::with_capacity(K_BATCHES);
    let mut oracle = SecureField::zero();
    for b in data.deep_batches.iter().take(K_BATCHES) {
        let m = M_COLS.min(b.cols.len());
        let zx = b.point.x;
        let zy = b.point.y;
        let denom_inv = denom_cm31(zx, zy, p.x, p.y).inverse();

        let mut cols = Vec::with_capacity(m);
        let mut numerator = SecureField::zero();
        for (&(col, a_real, b_real, c_real), &(v, pow)) in b.cols.iter().zip(&b.col_samples).take(m)
        {
            // Cross-check the validated derivation (4a) so the subset uses the
            // exact `(a,b,c)` the host oracle + the in-AIR derivation produce.
            let (a, bb, c) = line_coeffs(v, zy, pow);
            assert_eq!((a, bb, c), (a_real, b_real, c_real), "line-coeff mismatch");
            let leaf = queried_flat[col][qi];
            numerator += c * leaf - (a * p.y + bb);
            cols.push(ColTerm { v, pow, leaf });
        }
        oracle += numerator.mul_cm31(denom_inv);
        batches.push(Batch { zx, zy, cols });
    }

    DeepSubset {
        p_x: p.x,
        p_y: p.y,
        batches,
        oracle,
    }
}

// ── The multi-batch DEEP-numerator AIR ───────────────────────────────────────

#[derive(Clone)]
struct DeepAirEval {
    log_n_rows: u32,
    oracle: SecureField,
    /// `cols.len()` per batch (the subset shape, == fill order).
    batch_sizes: Vec<usize>,
}

impl FrameworkEval for DeepAirEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let zero = E::F::zero();
        let ef = E::combine_ef;
        let read_q =
            |eval: &mut E| -> [E::F; 4] { std::array::from_fn(|_| eval.next_trace_mask()) };
        // `conj(v) − v` for QM31 v = [v0,v1,v2,v3] is [0,0,−2v2,−2v3].
        let conj_minus_self = |v: &[E::F; 4]| -> E::EF {
            ef([
                zero.clone(),
                zero.clone(),
                zero.clone() - v[2].clone() - v[2].clone(),
                zero.clone() - v[3].clone() - v[3].clone(),
            ])
        };
        let lift = |f: E::F| -> E::EF { ef([f, zero.clone(), zero.clone(), zero.clone()]) };

        let p_x = eval.next_trace_mask();
        let p_y = eval.next_trace_mask();
        let p_y_ef = lift(p_y.clone());

        let mut acc = E::EF::zero();
        for &m in &self.batch_sizes {
            // Batch sample point z = (zx, zy), each QM31 = two CM31 = four M31.
            let zx_re_0 = eval.next_trace_mask();
            let zx_re_1 = eval.next_trace_mask();
            let zx_im_0 = eval.next_trace_mask();
            let zx_im_1 = eval.next_trace_mask();
            let zy_re_0 = eval.next_trace_mask();
            let zy_re_1 = eval.next_trace_mask();
            let zy_im_0 = eval.next_trace_mask();
            let zy_im_1 = eval.next_trace_mask();

            let zy = ef([
                zy_re_0.clone(),
                zy_re_1.clone(),
                zy_im_0.clone(),
                zy_im_1.clone(),
            ]);
            // raw_c = conj(z.y) − z.y, shared across the batch's columns.
            let raw_c = ef([
                zero.clone(),
                zero.clone(),
                zero.clone() - zy_im_0.clone() - zy_im_0.clone(),
                zero.clone() - zy_im_1.clone() - zy_im_1.clone(),
            ]);

            let mut numerator = E::EF::zero();
            for _ in 0..m {
                let value = read_q(&mut eval);
                let leaf = eval.next_trace_mask();
                let pow = read_q(&mut eval);
                let m1 = read_q(&mut eval); // value · raw_c
                let m2 = read_q(&mut eval); // raw_a · z.y
                let a = read_q(&mut eval); // pow · raw_a
                let b = read_q(&mut eval); // pow · raw_b
                let c = read_q(&mut eval); // pow · raw_c
                let qc = read_q(&mut eval); // leaf · c
                let ady = read_q(&mut eval); // a · p.y

                let raw_a = conj_minus_self(&value);
                let pow_ef = ef(pow);

                // raw_b = value·raw_c − raw_a·z.y (witnessed products m1, m2).
                let m1_ef = ef(m1);
                let m2_ef = ef(m2);
                eval.add_constraint(m1_ef.clone() - ef(value) * raw_c.clone());
                eval.add_constraint(m2_ef.clone() - raw_a.clone() * zy.clone());
                let raw_b = m1_ef - m2_ef;

                // (a,b,c) = pow · (raw_a, raw_b, raw_c).
                let a_ef = ef(a);
                let b_ef = ef(b);
                let c_ef = ef(c);
                eval.add_constraint(a_ef.clone() - pow_ef.clone() * raw_a);
                eval.add_constraint(b_ef.clone() - pow_ef.clone() * raw_b);
                eval.add_constraint(c_ef.clone() - pow_ef * raw_c.clone());

                // qc = leaf·c, ady = a·p.y (leaf, p.y are base field).
                let qc_ef = ef(qc);
                let ady_ef = ef(ady);
                eval.add_constraint(qc_ef.clone() - c_ef * lift(leaf));
                eval.add_constraint(ady_ef.clone() - a_ef * p_y_ef.clone());

                numerator += qc_ef - ady_ef - b_ef;
            }

            // ── In-AIR CM31 denominator: line(z, z̄)(p) ──
            // t1 = z.x.re − p.x, t2 = z.y.re − p.y (CM31, p lifted with 0 Im).
            let d_re = eval.next_trace_mask();
            let d_im = eval.next_trace_mask();
            let di_re = eval.next_trace_mask();
            let di_im = eval.next_trace_mask();

            let t1_0 = zx_re_0.clone() - p_x.clone();
            let t1_1 = zx_re_1.clone();
            let t2_0 = zy_re_0.clone() - p_y.clone();
            let t2_1 = zy_re_1.clone();
            // prod1 = t1 · z.y.im, prod2 = t2 · z.x.im (CM31 muls), denom = prod1−prod2.
            let prod1_re = t1_0.clone() * zy_im_0.clone() - t1_1.clone() * zy_im_1.clone();
            let prod1_im = t1_0 * zy_im_1.clone() + t1_1 * zy_im_0.clone();
            let prod2_re = t2_0.clone() * zx_im_0.clone() - t2_1.clone() * zx_im_1.clone();
            let prod2_im = t2_0 * zx_im_1.clone() + t2_1 * zx_im_0.clone();
            eval.add_constraint(d_re.clone() - (prod1_re - prod2_re)); // deg 2
            eval.add_constraint(d_im.clone() - (prod1_im - prod2_im));
            // denom_inv · denom == 1 (CM31): (di·d).re == 1, (di·d).im == 0.
            eval.add_constraint(
                di_re.clone() * d_re.clone() - di_im.clone() * d_im.clone() - E::F::one(),
            );
            eval.add_constraint(di_re.clone() * d_im.clone() + di_im.clone() * d_re.clone());

            // result = numerator · denom_inv (mul_cm31 = QM31 mul by [di_re,di_im,0,0]).
            let result = read_q(&mut eval);
            let result_ef = ef(result);
            let denom_inv = ef([di_re, di_im, zero.clone(), zero.clone()]);
            eval.add_constraint(result_ef.clone() - numerator * denom_inv); // deg 2
            acc += result_ef;
        }

        // The accumulated DEEP eval must equal the host oracle (the integration
        // binds this to the FRI fold chain's layer-0 `first_layer_evals[qi]`).
        eval.add_constraint(acc - E::EF::from(self.oracle));
        eval
    }
}

// ── Host trace fill (same order evaluate reads) ──────────────────────────────

fn push_q(row: &mut Vec<BaseField>, q: SecureField) {
    row.extend(q.to_m31_array());
}

fn row_values(d: &DeepSubset) -> Vec<BaseField> {
    let mut row = Vec::new();
    row.push(d.p_x);
    row.push(d.p_y);

    for batch in &d.batches {
        let zx = batch.zx.to_m31_array(); // [re0, re1, im0, im1]
        let zy = batch.zy.to_m31_array();
        row.extend(zx);
        row.extend(zy);

        let raw_c = batch.zy.complex_conjugate() - batch.zy;
        for col in &batch.cols {
            let raw_a = col.v.complex_conjugate() - col.v;
            let m1 = col.v * raw_c;
            let m2 = raw_a * batch.zy;
            let raw_b = m1 - m2;
            let a = col.pow * raw_a;
            let b = col.pow * raw_b;
            let c = col.pow * raw_c;
            let qc = c * SecureField::from(col.leaf);
            let ady = a * SecureField::from(d.p_y);

            push_q(&mut row, col.v);
            row.push(col.leaf);
            push_q(&mut row, col.pow);
            push_q(&mut row, m1);
            push_q(&mut row, m2);
            push_q(&mut row, a);
            push_q(&mut row, b);
            push_q(&mut row, c);
            push_q(&mut row, qc);
            push_q(&mut row, ady);
        }

        let denom = denom_cm31(batch.zx, batch.zy, d.p_x, d.p_y);
        let denom_inv = denom.inverse();
        row.push(denom.0);
        row.push(denom.1);
        row.push(denom_inv.0);
        row.push(denom_inv.1);

        let numerator: SecureField = batch
            .cols
            .iter()
            .map(|col| {
                let (a, b, c) = line_coeffs(col.v, batch.zy, col.pow);
                c * SecureField::from(col.leaf) - (a * SecureField::from(d.p_y) + b)
            })
            .sum();
        let result = numerator.mul_cm31(denom_inv);
        push_q(&mut row, result);
    }
    row
}

const TRACE_LOG: u32 = 6;

fn gen_trace(
    d: &DeepSubset,
    tamper_col: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let row = row_values(d);
    let n_cols = row.len();
    let n = 1usize << TRACE_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..n_cols)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    // Every row carries the same valid quotient (the oracle-match constraint is
    // not satisfied by zero padding).
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

fn batch_sizes(d: &DeepSubset) -> Vec<usize> {
    d.batches.iter().map(|b| b.cols.len()).collect()
}

fn prove_and_verify(d: &DeepSubset, tamper_col: Option<usize>) -> Result<(), String> {
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
    let component = FrameworkComponent::<DeepAirEval>::new(
        &mut TraceLocationAllocator::default(),
        DeepAirEval {
            log_n_rows: TRACE_LOG,
            oracle: d.oracle,
            batch_sizes: batch_sizes(d),
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
    stwo::core::verifier::verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// DIAGNOSTIC (the 4c layout decision): does the trace-decommit leaf order
/// (sorted by log size) align with the flattened/commit column order the DEEP
/// `col` index uses, and is the per-batch flat-index list monotone (the α-power
/// global order)? Prints per-tree log-size uniformity + the batch column-index
/// structure so the leaf-row coupling layout can be designed against real shapes.
#[test]
#[ignore = "diagnostic: prints real-segment decommit/DEEP column structure"]
fn deep_layout_diagnostic() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);

    eprintln!("── per-tree column log sizes (sorted==commit?) ──");
    let mut tree_offsets = Vec::new();
    let mut acc = 0usize;
    for (t, cls) in data.tree_column_log_sizes.iter().enumerate() {
        tree_offsets.push(acc);
        acc += cls.len();
        let mut distinct: Vec<u32> = cls.clone();
        distinct.sort_unstable();
        distinct.dedup();
        let mut order: Vec<usize> = (0..cls.len()).collect();
        order.sort_by_key(|&c| cls[c]);
        let identity = order.iter().enumerate().all(|(i, &c)| i == c);
        eprintln!(
            "  tree {t}: {} cols, height {}, distinct log sizes {:?}, sorted==commit: {identity}",
            cls.len(),
            data.tree_heights[t],
            distinct,
        );
    }
    eprintln!("flat column offsets per tree: {tree_offsets:?} (total {acc})");

    eprintln!("── DEEP batches: flat-index structure ──");
    let mut all_first: Vec<usize> = Vec::new();
    for (bi, b) in data.deep_batches.iter().enumerate() {
        let idxs: Vec<usize> = b.cols.iter().map(|c| c.0).collect();
        let monotone = idxs.windows(2).all(|w| w[0] < w[1]);
        let min = *idxs.iter().min().unwrap();
        let max = *idxs.iter().max().unwrap();
        let contiguous = max - min + 1 == idxs.len();
        all_first.push(min);
        if bi < 6 || bi + 2 >= data.deep_batches.len() {
            eprintln!(
                "  batch {bi}: {} cols, flat idx [{min}..={max}], monotone {monotone}, \
                 contiguous {contiguous}",
                idxs.len(),
            );
        }
    }
    eprintln!(
        "── {} batches total; the per-query first_layer_evals bind to these. \
         The α-power index is the global flat order; cross-batch monotone-min: {} ──",
        data.deep_batches.len(),
        all_first.windows(2).all(|w| w[0] <= w[1]),
    );

    // Which trees does each batch's columns come from?
    let which_tree =
        |flat: usize| -> usize { tree_offsets.iter().rposition(|&o| flat >= o).unwrap_or(0) };
    for (bi, b) in data.deep_batches.iter().enumerate().take(4) {
        let mut tcount = [0usize; 8];
        for c in &b.cols {
            tcount[which_tree(c.0)] += 1;
        }
        eprintln!(
            "  batch {bi} columns by tree: {:?}",
            &tcount[..data.tree_heights.len()]
        );
    }
}

/// FAST: the real multi-batch DEEP-numerator trace satisfies the AIR.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn deep_air_satisfied() {
    let d = extract();
    let trace = gen_trace(&d, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = DeepAirEval {
        log_n_rows: TRACE_LOG,
        oracle: d.oracle,
        batch_sizes: batch_sizes(&d),
    };
    assert_constraints_on_trace(
        &tv,
        TRACE_LOG,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
    let n_terms: usize = d.batches.iter().map(|b| b.cols.len()).sum();
    eprintln!(
        "deep_air_satisfied: in-AIR multi-batch DEEP numerator over {} batches / {n_terms} terms \
         (real OODS samples, in-AIR CM31 denom from (z,p)) matches the host oracle ({:?}); trace \
         satisfies the AIR.",
        d.batches.len(),
        d.oracle,
    );
}

/// THE GATE: the in-AIR multi-batch DEEP numerator (real OODS data, in-AIR CM31
/// denom derived from the batch point z + the query domain point p) proves+verifies
/// through the lifted Poseidon2-M31 protocol at degree ≤ 2; a perturbed leaf is
/// rejected.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn deep_air_gate() {
    let d = extract();
    prove_and_verify(&d, None).expect("honest multi-batch DEEP numerator must prove+verify");

    // The first batch's first column's leaf sits after p_x,p_y (2) + z(8) + value(4).
    let leaf0_col = 2 + 8 + 4;
    assert!(
        prove_and_verify(&d, Some(leaf0_col)).is_err(),
        "a perturbed trace leaf must be rejected"
    );

    let n_terms: usize = d.batches.iter().map(|b| b.cols.len()).sum();
    eprintln!(
        "deep_air_gate GREEN: a REAL canonical segment's multi-batch DEEP numerator ({} batches, \
         {n_terms} (batch,col) terms) — (a,b,c) derived in-AIR from (v, z.y, α^i), the per-batch \
         CM31 denominator line(z,z̄)(p) derived in-AIR from the batch point z + the query domain \
         point p (its inverse witnessed), the numerator·denom_inv accumulated across batches and \
         bound to the host oracle — proves+verifies through the lifted Poseidon2-M31 protocol at \
         degree ≤ 2; a perturbed leaf is rejected.",
        d.batches.len(),
    );
}
