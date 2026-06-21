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

use num_traits::One;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;
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
