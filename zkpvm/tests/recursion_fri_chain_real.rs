//! Recursion build P5.3 — **the FRI fold chain at REAL scale (step 3, part 1).**
//!
//! `fri_fold_chain.rs` proved the cross-layer FRI fold mechanism on a SYNTHETIC
//! low-degree instance (3 folds: 1 circle + 2 line). This file scales it to a REAL
//! canonical segment's FRI proof: **14 layers (1 circle + 13 line), 38 queries**,
//! fed by `extract_recursion_data` (`first_layer_evals` = the DEEP quotients =
//! layer-0 input, `fold_alphas` = the 14 per-layer folding challenges,
//! `query_positions`) + the raw per-layer `fri_witness` siblings + the real
//! `last_layer_poly` (a degree-0 constant).
//!
//! This part (HOST reconstruction) replicates the verifier's per-layer fold
//! (`fri.rs` `decommit_inner_layers`: group queries by sibling-pair subset, fill
//! each subset from the running evals or the `fri_witness`, fold circle→line then
//! line→line, halve the query index each layer) and VALIDATES it against the real
//! decommit: every query's final folded value must equal the last-layer constant —
//! which the real `FriVerifier::decommit` (run inside `extract_recursion_data`)
//! guarantees. So a match proves the reconstruction reproduces the real verifier's
//! fold chain. The fold uses the closed form `(f_a+f_b) + α·((f_a−f_b)·twid)` with
//! the per-layer coset twiddle (the proven `fri_fold_chain.rs` recipe).
//!
//! The in-AIR fold chain (the proven gadget, generalised to 14 layers) + the
//! coupled FRI-layer Merkle decommit (4-wide QM31 leaves, `fold_step=1` ⇒ no
//! packing) ride on this reconstruction's per-query (e0,e1,bit) records — built
//! next.
//!
//! Run: `cargo test -p zkpvm --release --features poseidon2-channel --test \
//!     recursion_fri_chain_real -- --ignored --nocapture`

#![cfg(feature = "poseidon2-channel")]

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::{P2MerkleChannel, Poseidon2M31Channel, mobile_config};
use stwo::core::air::Component;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::poly::circle::CanonicCoset;
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
use zkpvm::{Proof, SideNote, extract_recursion_data};

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

// ── Per-layer coset geometry for the twiddle (the fri_fold_chain.rs recipe). ──

/// `domain_point(idx)` over a line coset via the conditional-point-add chain.
struct CosetConsts {
    initial: CirclePoint<BaseField>,
    q_pts: Vec<CirclePoint<BaseField>>,
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

/// The line-domain point at line-coset index `idx` (`idx` < 2^L): start at
/// `initial`, add `q_pts[k]` for each set bit of `idx` (LSB-first). Matches
/// `domain.at(bit_reverse_index(idx, L))`.
fn point_at(c: &CosetConsts, idx: usize) -> CirclePoint<BaseField> {
    let mut pt = c.initial;
    for (k, q) in c.q_pts.iter().enumerate() {
        if (idx >> k) & 1 == 1 {
            pt = pt + *q;
        }
    }
    pt
}

/// One closed-form fold step: `(f_a+f_b) + α·((f_a−f_b)·twid)`.
fn fold_step(
    f_a: SecureField,
    f_b: SecureField,
    alpha: SecureField,
    twid: BaseField,
) -> SecureField {
    (f_a + f_b) + alpha * ((f_a - f_b) * twid)
}

/// Per-query, per-layer fold record: the sibling-pair evals (position order),
/// the query's parity bit at this layer, and the folded output.
#[derive(Clone, Copy, Debug)]
struct LayerRec {
    pos: usize,      // the query's position at this layer (subset_start = pos & !1)
    e0: SecureField, // eval at the even position of the subset
    e1: SecureField, // eval at the odd position
    bit: u32,        // the query's position parity at this layer
    folded: SecureField,
}

struct FriChain {
    first_log: u32,
    n_layers: usize,
    /// Per query (38), a 14-entry fold record.
    per_query: Vec<Vec<LayerRec>>,
    /// The line cosets for the twiddle gadget: index 0 used by the circle layer
    /// AND inner layer 0; inner layer i uses `line_cosets[i]`.
    line_cosets: Vec<CosetConsts>,
    last_layer_const: SecureField,
    last_layer_domain: LineDomain,
}

/// Replicate the verifier's per-layer fold from the real FRI proof data, recording
/// per-query (e0,e1,bit,folded) at each of the 14 layers.
fn reconstruct(proof: &Proof, data: &zkpvm::RecursionData) -> FriChain {
    let fp = &proof.stark_proof.fri_proof;
    let first_log = data.lifting_log_size; // 16
    let n_inner = fp.inner_layers.len();
    let n_layers = 1 + n_inner; // 14
    let alphas = &data.fold_alphas; // 14
    assert_eq!(alphas.len(), n_layers, "one fold alpha per layer");

    // Line cosets: line_cosets[0] = LineDomain::new(circle.half_coset) [log first_log-1];
    // line_cosets[i] = line_cosets[0].double()^i (the inner layer domains).
    let circle_domain = CanonicCoset::new(first_log).circle_domain();
    let mut line_domain = LineDomain::new(circle_domain.half_coset);
    let mut line_cosets = Vec::new();
    let mut line_domains = Vec::new();
    for _ in 0..n_inner {
        line_cosets.push(coset_consts(&line_domain));
        line_domains.push(line_domain);
        line_domain = line_domain.double();
    }
    let last_layer_domain = line_domain; // after n_inner line folds
    let last_layer_const = {
        // last_layer_poly is degree 0 ⇒ eval_at_point is the constant for any x.
        let x = last_layer_domain.at(0);
        fp.last_layer_poly.eval_at_point(x.into())
    };

    // Global reconstruction: distinct sorted positions, running evals, fold per
    // layer; capture per-position (e0,e1,folded,queried-parity) maps.
    let mut positions: Vec<usize> = data.query_positions.clone();
    let mut evals: Vec<SecureField> = data.first_layer_evals.clone();
    assert_eq!(positions.len(), evals.len());
    // For each layer, position(at that layer) → (e0, e1, folded). A query reads its
    // record by its position; bit = position parity.
    let mut layer_maps: Vec<
        std::collections::HashMap<usize, (SecureField, SecureField, SecureField)>,
    > = Vec::with_capacity(n_layers);

    for layer in 0..n_layers {
        let alpha = alphas[layer];
        let fri_witness: &[SecureField] = if layer == 0 {
            &fp.first_layer.fri_witness
        } else {
            &fp.inner_layers[layer - 1].fri_witness
        };
        let mut wit = fri_witness.iter().copied();
        let mut map = std::collections::HashMap::new();
        let mut next_pos = Vec::new();
        let mut next_ev = Vec::new();
        let mut i = 0;
        while i < positions.len() {
            let start = (positions[i] >> 1) << 1;
            // Gather the subset {start, start+1} in position order.
            let mut sub = [SecureField::one(); 2];
            for (off, slot) in sub.iter_mut().enumerate() {
                let p = start + off;
                if i < positions.len() && positions[i] == p {
                    *slot = evals[i];
                    i += 1;
                } else {
                    *slot = wit.next().expect("fri_witness exhausted");
                }
            }
            let (e0, e1) = (sub[0], sub[1]);
            // Twiddle: layer 0 (circle) uses line_cosets[0] .y at index start>>1;
            // inner layer L uses line_cosets[L-1] .x at index start (subset_start).
            let folded = if layer == 0 {
                let p = point_at(&line_cosets[0], start >> 1);
                fold_step(e0, e1, alpha, p.y.inverse())
            } else {
                let p = point_at(&line_cosets[layer - 1], start);
                fold_step(e0, e1, alpha, p.x.inverse())
            };
            map.insert(start >> 1, (e0, e1, folded));
            next_pos.push(start >> 1);
            next_ev.push(folded);
        }
        layer_maps.push(map);
        positions = next_pos;
        evals = next_ev;
    }

    // The surviving evals (one per distinct last-layer position) must all equal the
    // last-layer constant — the real decommit's `decommit_last_layer` check.
    for (p, e) in positions.iter().zip(&evals) {
        let x = last_layer_domain.at(bit_reverse_index(*p, last_layer_domain.log_size()));
        let expected = fp.last_layer_poly.eval_at_point(x.into());
        assert_eq!(
            *e, expected,
            "reconstructed last-layer eval must match poly"
        );
    }

    // Per-query chains: follow each original query's position down the layers.
    let per_query: Vec<Vec<LayerRec>> = data
        .query_positions
        .iter()
        .map(|&q0| {
            let mut pos = q0;
            (0..n_layers)
                .map(|layer| {
                    let sub = pos >> 1;
                    let (e0, e1, folded) = layer_maps[layer][&sub];
                    let rec = LayerRec {
                        pos,
                        e0,
                        e1,
                        bit: (pos & 1) as u32,
                        folded,
                    };
                    pos = sub;
                    rec
                })
                .collect()
        })
        .collect();

    FriChain {
        first_log,
        n_layers,
        per_query,
        line_cosets,
        last_layer_const,
        last_layer_domain,
    }
}

/// HOST validation: the reconstruction reproduces the real verifier's fold chain.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn fri_chain_real_reconstruct() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let chain = reconstruct(&proof, &data);

    // Per-query end-to-end cross-check: layer 0 input = first_layer_evals[q]
    // (selected from the subset by the query's bit), each fold chains into the
    // next layer's queried eval, and the final folded == the last-layer constant.
    for (qi, recs) in chain.per_query.iter().enumerate() {
        assert_eq!(recs.len(), chain.n_layers);
        // layer-0 input matches first_layer_evals (selected by bit).
        let l0 = recs[0];
        let input0 = if l0.bit == 0 { l0.e0 } else { l0.e1 };
        assert_eq!(
            input0, data.first_layer_evals[qi],
            "layer-0 queried eval must be first_layer_evals[{qi}]"
        );
        // chain: folded[L] feeds layer L+1's queried eval.
        for layer in 0..chain.n_layers - 1 {
            let cur = recs[layer];
            let nxt = recs[layer + 1];
            let nxt_input = if nxt.bit == 0 { nxt.e0 } else { nxt.e1 };
            assert_eq!(cur.folded, nxt_input, "fold chain query {qi} layer {layer}");
            // closed-form fold reproduces the recorded folded (twiddle from the
            // query's ACTUAL position at this layer: circle uses .y at subset
            // index pos>>1, line uses .x at subset_start pos & !1).
            let twid = if layer == 0 {
                point_at(&chain.line_cosets[0], cur.pos >> 1).y.inverse()
            } else {
                point_at(&chain.line_cosets[layer - 1], cur.pos & !1)
                    .x
                    .inverse()
            };
            assert_eq!(
                cur.folded,
                fold_step(cur.e0, cur.e1, data.fold_alphas[layer], twid),
                "closed-form fold query {qi} layer {layer}"
            );
        }
        // last layer folded == the last-layer constant.
        assert_eq!(
            recs[chain.n_layers - 1].folded,
            chain.last_layer_const,
            "query {qi} final fold must equal the last-layer constant"
        );
    }

    eprintln!(
        "fri_chain_real_reconstruct GREEN: the REAL {}-layer FRI fold chain (1 circle + {} line, \
         {} queries, last layer degree-0 constant) reconstructs from extract_recursion_data \
         (first_layer_evals + fold_alphas + query_positions) + the raw fri_witness siblings — \
         every query's chain folds down to the last-layer constant, matching the real \
         FriVerifier::decommit. first_log {}, last_layer log {}.",
        chain.n_layers,
        chain.n_layers - 1,
        chain.per_query.len(),
        chain.first_log,
        chain.last_layer_domain.log_size(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The in-AIR 14-layer fold chain (twiddle derived per layer; constant alphas).
// ─────────────────────────────────────────────────────────────────────────────

impl Clone for CosetConsts {
    fn clone(&self) -> Self {
        CosetConsts {
            initial: self.initial,
            q_pts: self.q_pts.clone(),
        }
    }
}

/// The bit-sources driving layer `L`'s twiddle point-chain: layer 0 (circle) uses
/// q-bits `[1, first_log)`; inner layer `L` uses `[forced-0, bits[L+1..first_log)]`
/// (the subset_start index). `None` = a forced-zero entry.
fn layer_bit_sources(layer: usize, first_log: u32) -> Vec<Option<usize>> {
    let fl = first_log as usize;
    if layer == 0 {
        (1..fl).map(Some).collect()
    } else {
        std::iter::once(None)
            .chain((layer + 1..fl).map(Some))
            .collect()
    }
}

/// In-AIR conditional-point-add chain (the proven `fri_fold_chain` gadget): reads
/// `bits.len()` witnessed points, binds each to `pt_k = bits[k] ? pt_{k-1}+q_pts[k]
/// : pt_{k-1}` (degree 2). Returns the final `(x, y)`.
fn point_chain<E: EvalAtRow>(eval: &mut E, consts: &CosetConsts, bits: &[E::F]) -> (E::F, E::F) {
    let mut prev_x = E::F::from(consts.initial.x);
    let mut prev_y = E::F::from(consts.initial.y);
    for (k, bit) in bits.iter().enumerate() {
        let qkx = consts.q_pts[k].x;
        let qky = consts.q_pts[k].y;
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

#[derive(Clone)]
struct FriChainEval {
    log_n_rows: u32,
    first_log: u32,
    n_layers: usize,
    line_cosets: Vec<CosetConsts>,
    alphas: Vec<SecureField>,
    last_layer_const: SecureField,
}

impl FrameworkEval for FriChainEval {
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

        // q + its first_log boolean bits (recompose ⇒ binds the bits).
        let q = eval.next_trace_mask();
        let bits: Vec<E::F> = (0..self.first_log)
            .map(|_| eval.next_trace_mask())
            .collect();
        let mut recompose = E::F::zero();
        let mut coeff = BaseField::one();
        for bit in &bits {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            recompose += bit.clone() * coeff;
            coeff += coeff;
        }
        eval.add_constraint(recompose - q);

        // One fold step (constant alpha): scaled/prod/folded witnessed, deg ≤ 2.
        let fold_step_air = |eval: &mut E,
                             f_a: &[E::F; 4],
                             f_b: &[E::F; 4],
                             alpha: SecureField,
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
            eval.add_constraint(
                E::combine_ef(prod.clone()) - E::EF::from(alpha) * E::combine_ef(scaled),
            );
            eval.add_constraint(
                E::combine_ef(folded.clone())
                    - (E::combine_ef(f_a.clone())
                        + E::combine_ef(f_b.clone())
                        + E::combine_ef(prod)),
            );
            folded
        };
        let inv_of = |eval: &mut E, coord: E::F| -> E::F {
            let t = eval.next_trace_mask();
            eval.add_constraint(t.clone() * coord - one.clone());
            t
        };

        let mut prev_folded: Option<[E::F; 4]> = None;
        for layer in 0..self.n_layers {
            let e0 = read4(&mut eval);
            let e1 = read4(&mut eval);
            // Chain: the query's eval at this layer = select(bit[layer], e0, e1);
            // for layer > 0 it must equal the previous layer's folded output.
            if let Some(pf) = &prev_folded {
                for k in 0..4 {
                    let queried =
                        e0[k].clone() + bits[layer].clone() * (e1[k].clone() - e0[k].clone());
                    eval.add_constraint(pf[k].clone() - queried);
                }
            }
            // Twiddle: derive the layer's coset point from the (bound) q-bits.
            let srcs = layer_bit_sources(layer, self.first_log);
            let layer_bits: Vec<E::F> = srcs
                .iter()
                .map(|s| match s {
                    Some(k) => bits[*k].clone(),
                    None => zero.clone(),
                })
                .collect();
            let coset = if layer == 0 {
                &self.line_cosets[0]
            } else {
                &self.line_cosets[layer - 1]
            };
            let (px, py) = point_chain(&mut eval, coset, &layer_bits);
            let twid = inv_of(&mut eval, if layer == 0 { py } else { px });
            let folded = fold_step_air(&mut eval, &e0, &e1, self.alphas[layer], twid);
            prev_folded = Some(folded);
        }
        // Last layer: the surviving folded eval == the degree-0 last-layer constant.
        let last = prev_folded.expect("at least one layer");
        eval.add_constraint(E::combine_ef(last) - E::EF::from(self.last_layer_const));
        eval
    }
}

// ── Host trace fill (same order the eval reads) ───────────────────────────────

fn point_chain_host(consts: &CosetConsts, bits: &[u32]) -> Vec<CirclePoint<BaseField>> {
    let mut pt = consts.initial;
    let mut out = Vec::with_capacity(bits.len());
    for (k, &b) in bits.iter().enumerate() {
        if b == 1 {
            pt = pt + consts.q_pts[k];
        }
        let _ = k;
        out.push(pt);
    }
    out
}

fn push4(row: &mut Vec<BaseField>, q: SecureField) {
    row.extend(q.to_m31_array());
}

/// One query's full fold-chain row (same order `FriChainEval::evaluate` reads).
fn fri_row(chain: &FriChain, alphas: &[SecureField], recs: &[LayerRec]) -> Vec<BaseField> {
    let q = recs[0].pos;
    let mut row = Vec::new();
    row.push(BaseField::from(q as u32));
    for k in 0..chain.first_log {
        row.push(BaseField::from((q >> k) & 1));
    }
    for (layer, rec) in recs.iter().enumerate() {
        push4(&mut row, rec.e0);
        push4(&mut row, rec.e1);
        // point chain + twiddle
        let srcs = layer_bit_sources(layer, chain.first_log);
        let bit_vals: Vec<u32> = srcs
            .iter()
            .map(|s| s.map_or(0, |k| ((q >> k) & 1) as u32))
            .collect();
        let coset = if layer == 0 {
            &chain.line_cosets[0]
        } else {
            &chain.line_cosets[layer - 1]
        };
        let pts = point_chain_host(coset, &bit_vals);
        let last_pt = *pts.last().unwrap();
        for p in &pts {
            row.push(p.x);
            row.push(p.y);
        }
        let twid = if layer == 0 {
            last_pt.y.inverse()
        } else {
            last_pt.x.inverse()
        };
        row.push(twid);
        let scaled = (rec.e0 - rec.e1) * twid;
        let prod = alphas[layer] * scaled;
        let folded = (rec.e0 + rec.e1) + prod;
        debug_assert_eq!(folded, rec.folded, "host fold must match reconstruction");
        push4(&mut row, scaled);
        push4(&mut row, prod);
        push4(&mut row, folded);
    }
    row
}

fn fri_n_cols(chain: &FriChain) -> usize {
    let mut n = 1 + chain.first_log as usize; // q + bits
    for layer in 0..chain.n_layers {
        let pts = layer_bit_sources(layer, chain.first_log).len();
        n += 8 + pts * 2 + 1 + 12; // e0,e1 + chain + twid + scaled,prod,folded
    }
    n
}

fn fri_gen_trace(
    chain: &FriChain,
    alphas: &[SecureField],
    log_size: u32,
    tamper: Option<(usize, usize)>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << log_size;
    let n_cols = fri_n_cols(chain);
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..n_cols)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for r in 0..n {
        let recs = &chain.per_query[r % chain.per_query.len()];
        for (c, v) in fri_row(chain, alphas, recs).into_iter().enumerate() {
            cols[c].set(r, v);
        }
    }
    if let Some((c, r)) = tamper {
        let orig = cols[c].at(r);
        cols[c].set(r, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

fn fri_eval(chain: &FriChain, alphas: &[SecureField], log_size: u32) -> FriChainEval {
    FriChainEval {
        log_n_rows: log_size,
        first_log: chain.first_log,
        n_layers: chain.n_layers,
        line_cosets: chain.line_cosets.clone(),
        alphas: alphas.to_vec(),
        last_layer_const: chain.last_layer_const,
    }
}

fn fri_prove_and_verify(
    chain: &FriChain,
    alphas: &[SecureField],
    tamper: Option<(usize, usize)>,
) -> Result<(), String> {
    let config = mobile_config();
    let log_size = (chain.per_query.len() as u32)
        .next_power_of_two()
        .trailing_zeros()
        .max(1);
    let trace = fri_gen_trace(chain, alphas, log_size, tamper);
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
    let component = FrameworkComponent::<FriChainEval>::new(
        &mut TraceLocationAllocator::default(),
        fri_eval(chain, alphas, log_size),
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

/// FAST: the real 14-layer fold-chain trace satisfies the AIR.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn fri_chain_real_air_satisfied() {
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let chain = reconstruct(&proof, &data);
    let alphas = data.fold_alphas.clone();
    let log_size = (chain.per_query.len() as u32)
        .next_power_of_two()
        .trailing_zeros()
        .max(1);
    let trace = fri_gen_trace(&chain, &alphas, log_size, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let ev = fri_eval(&chain, &alphas, log_size);
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            ev.evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "fri_chain_real_air_satisfied: the REAL {}-layer fold chain ({} queries, {} cols/row, log \
         {log_size}) satisfies the AIR (twiddle derived in-AIR per layer from q).",
        chain.n_layers,
        chain.per_query.len(),
        fri_n_cols(&chain),
    );
}

/// THE GATE: the real 14-layer FRI fold chain reproduces in-AIR, proves+verifies
/// through the lifted Poseidon2-M31 protocol; a perturbed fold output is rejected.
#[test]
#[ignore = "heavy: real-segment FRI fold chain prove+verify (release)"]
fn fri_chain_real_gate() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let chain = reconstruct(&proof, &data);
    let alphas = data.fold_alphas.clone();

    fri_prove_and_verify(&chain, &alphas, None).expect("honest real FRI fold chain");

    // Perturb the layer-0 folded[0] column (q,bits + e0,e1 + chain pts + twid +
    // scaled,prod, then folded) at row 0 — breaks the chain + last-layer check.
    let pts0 = layer_bit_sources(0, chain.first_log).len();
    let folded0_col = (1 + chain.first_log as usize) + 8 + pts0 * 2 + 1 + 8;
    assert!(
        fri_prove_and_verify(&chain, &alphas, Some((folded0_col, 0))).is_err(),
        "a perturbed fold output must be rejected"
    );

    eprintln!(
        "fri_chain_real_gate GREEN: the REAL {}-layer FRI fold chain (1 circle + {} line, {} \
         queries, twiddle derived in-AIR per layer, cross-layer chained, last layer a degree-0 \
         constant) reproduces in-AIR and proves+verifies through the lifted Poseidon2-M31 protocol \
         at degree ≤ 2; a perturbed fold is rejected.",
        chain.n_layers,
        chain.n_layers - 1,
        chain.per_query.len(),
    );
}
