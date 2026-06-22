#![cfg(feature = "poseidon2-channel")]

//! Recursion build P5.3 — **step 3b de-risk: the FRI-layer Merkle decommit COUPLED
//! to the fold chain (standalone).**
//!
//! `recursion_fri_chain_real` proved the 14-layer FRI fold chain with the
//! sibling-pair evals `(e0,e1)` HOST-supplied (trusted). This file closes that gap:
//! every fold input `(e0,e1)` is a leaf of the layer's committed FRI Merkle tree,
//! re-hashed in-AIR to the (here preprocessed-pinned; transcript-bound at
//! integration) layer root — so a prover cannot fold fabricated evals.
//!
//! THE COUPLING DESIGN (the open layout question, resolved):
//!   * **Per-(query,layer) coset stream.** The verifier decommits each queried
//!     coset `{2k, 2k+1}` (BOTH evals are leaves of layer L's tree). We stream each
//!     coset as: `sponge(e0@2k)` → `sponge(e1@2k+1)` → a MERGE row
//!     `hash_children(h0,h1)` → the climb to the root. The two leaf hashes h0,h1 are
//!     materialised into an `lh` column on the sponge rows and read by the merge row
//!     at fixed offsets `[-2]` / `[-1]` (the offset-spike-proven cross-row read).
//!     One perm/row, the 16-wide state threaded by the `[0,1]` latch (the
//!     `recursion_decommit_scale` gadget) + a single MERGE row type.
//!   * **Co-located fold step.** The fold for `(query,layer)` rides on that coset's
//!     `e0`-sponge row: `e0 = chunk@[0]` (this row's leaf value), `e1 = chunk@[1]`
//!     (the next row = the e1 sponge). So `e0`/`e1` ARE the decommitted leaf chunks —
//!     authenticated by construction, NO separate coupling constraint.
//!   * **Twiddle is HOST, FORCED by consistency.** With both coset leaves decommitted
//!     at every layer, the cross-layer chain (`folded[L]` == the running leaf at
//!     `L+1`), and the last-layer check, the fold twiddle is uniquely forced
//!     (`alpha·(e0−e1)·(twid−twid*) = 0`, `alpha≠0`, generically `e0≠e1`) — so it
//!     need NOT be derived in-AIR (no point-chain). This removes the heaviest gadget.
//!   * **Cross-layer carry latch.** `folded[L]` is carried across the coset's
//!     decommit rows to layer `L+1`'s fold row via a held `carry` column
//!     (`carry[next] = is_fold ? folded : carry[cur]`, the cycle closed by the fill).
//!     At `L>0` the running leaf `select(bit, e0, e1)` is bound to `carry` (the chain);
//!     at the last layer `folded == last_layer_const`. The carry resets per query
//!     (layer 0 has no running check, and overwrites carry to `folded[0]`).
//!   * **alpha selection.** Each fold row's layer is a preprocessed `is_layer[L]`
//!     one-hot; `alpha_sel = Σ is_layer[L]·alpha_lat[L]` (witnessed, deg 2), so
//!     `prod = alpha_sel·scaled` stays deg 2.
//!
//! All constraints degree ≤ 2; `assert_constraints` only checks zero-ness, so the
//! milestone is the PROVE. Run:
//! `cargo test -p zkpvm --release --features poseidon2-channel --test \
//!     recursion_fri_decommit -- --ignored --nocapture`

mod recursion_common;

use std::collections::HashMap;

use num_traits::{One, Zero};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel, eval_permutation,
    hash_children_m31, mobile_config, permute, record_permutation,
};
use stwo::core::air::Component;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    assert_constraints_on_trace, preprocessed_columns::PreProcessedColumnId,
};
use zkpvm::{Proof, SideNote, extract_recursion_data};

fn canonical_segment() -> (Proof, SideNote) {
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::prove_canonical;

    let code = vec![
        Opcode::Add64 as u8, 0x10, 2,
        Opcode::Add64 as u8, 0x12, 3,
        Opcode::Add64 as u8, 0x13, 4,
        Opcode::Add64 as u8, 0x14, 5,
        Opcode::Add64 as u8, 0x15, 6,
        Opcode::Add64 as u8, 0x16, 7,
        Opcode::Trap as u8,
    ];
    let bitmask: Vec<u8> = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1];
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 100;
    regs[1] = 1;
    let initial_memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, initial_memory.clone(), 10_000, 25);
    let mut tracing = TracingPvm::new(pvm);
    assert_eq!(tracing.run(), javm::ExitReason::Trap);
    let steps = tracing.into_trace();
    let mut sn = SideNote::new(steps, code, bitmask).with_memory(initial_memory);
    let proof = prove_canonical(&mut sn, &[]).expect("prove_canonical under Poseidon2-M31");
    (proof, sn)
}

// ── Per-layer coset geometry for the host twiddle (the fri_fold_chain recipe). ──
struct CosetConsts {
    initial: CirclePoint<BaseField>,
    q_pts: Vec<CirclePoint<BaseField>>,
}
fn coset_consts(domain: &LineDomain) -> CosetConsts {
    let coset = domain.coset();
    let l = domain.log_size();
    let initial = coset.initial_index.to_point();
    let q_pts = (0..l).map(|k| (coset.step_size * (1usize << (l - 1 - k))).to_point()).collect();
    CosetConsts { initial, q_pts }
}
fn point_at(c: &CosetConsts, idx: usize) -> CirclePoint<BaseField> {
    let mut pt = c.initial;
    for (k, q) in c.q_pts.iter().enumerate() {
        if (idx >> k) & 1 == 1 {
            pt = pt + *q;
        }
    }
    pt
}

type Hash8 = [BaseField; 8];

fn sponge_leaf(row: &[BaseField]) -> Hash8 {
    let mut h = P2MerkleHasher::default();
    h.update_leaf(row);
    h.finalize().0
}

/// Node map for a Merkle tree from sorted leaf positions, leaf values, witnesses
/// (the `recursion_decommit_scale` replay; for FRI every queried coset has BOTH
/// leaves present, so level-0 merges consume no witness and all witnesses are at
/// level ≥ 1).
fn decommit_node_map(
    height: u32,
    root: Hash8,
    positions: &[usize],
    leaf_vals: &[SecureField],
    hash_witness: &[Hash8],
) -> Vec<HashMap<usize, Hash8>> {
    let mut node_map: Vec<HashMap<usize, Hash8>> = vec![HashMap::new(); (height + 1) as usize];
    let mut layer: Vec<(usize, Hash8)> = Vec::new();
    for (i, &pos) in positions.iter().enumerate() {
        let row = leaf_vals[i].to_m31_array().to_vec();
        let leaf = sponge_leaf(&row);
        layer.push((pos, leaf));
        node_map[0].insert(pos, leaf);
    }
    let mut witness = hash_witness.iter();
    for level in 0..height as usize {
        let mut next: Vec<(usize, Hash8)> = Vec::new();
        let mut idx = 0;
        while idx < layer.len() {
            let (i0, h0) = layer[idx];
            let (children, consumed) = if idx + 1 < layer.len() && (i0 ^ 1) == layer[idx + 1].0 {
                ((h0, layer[idx + 1].1), 2)
            } else {
                let w = *witness.next().expect("witness too short");
                node_map[level].insert(i0 ^ 1, w);
                (if i0 & 1 == 0 { (h0, w) } else { (w, h0) }, 1)
            };
            let parent = hash_children_m31(&children.0, &children.1);
            next.push((i0 >> 1, parent));
            node_map[level + 1].insert(i0 >> 1, parent);
            idx += consumed;
        }
        layer = next;
    }
    assert!(witness.next().is_none(), "witness not fully consumed");
    assert_eq!(layer.len(), 1, "fold must reach a single root");
    assert_eq!(layer[0].1, root, "recomputed FRI-layer root must equal the commitment");
    node_map
}

/// One FRI layer's decommit tree (node map keyed by [level][position]).
struct LayerTree {
    height: u32,
    root: Hash8,
    node_map: Vec<HashMap<usize, Hash8>>,
}

/// One fold step (query, layer): the coset subset index `k` (= pos>>1), the two
/// coset evals, the running parity bit, the host twiddle, the folded output.
#[derive(Clone, Copy)]
struct FoldRec {
    layer: usize,
    k: usize,
    e0: SecureField,
    e1: SecureField,
    bit: u32,
    twid: BaseField,
    folded: SecureField,
}

struct FriData {
    n_layers: usize,
    layers: Vec<LayerTree>,
    per_query: Vec<Vec<FoldRec>>,
    last_layer_const: SecureField,
}

/// Reconstruct the per-layer fold (the `recursion_fri_chain_real` replay) AND build
/// each layer's decommit node map from the real `fri_witness` + decommitments.
fn reconstruct(proof: &Proof, data: &zkpvm::RecursionData) -> FriData {
    let fp = &proof.stark_proof.fri_proof;
    let first_log = data.lifting_log_size;
    let n_inner = fp.inner_layers.len();
    let n_layers = 1 + n_inner;
    let alphas = &data.fold_alphas;
    assert_eq!(alphas.len(), n_layers, "one fold alpha per layer");

    let circle_domain = CanonicCoset::new(first_log).circle_domain();
    let mut line_domain = LineDomain::new(circle_domain.half_coset);
    let mut line_cosets = Vec::new();
    for _ in 0..n_inner {
        line_cosets.push(coset_consts(&line_domain));
        line_domain = line_domain.double();
    }
    let last_layer_domain = line_domain;
    let last_layer_const = fp.last_layer_poly.eval_at_point(last_layer_domain.at(0).into());

    // Per layer: subset map k -> (e0, e1, folded) AND the decommit positions list.
    let mut positions: Vec<usize> = data.query_positions.clone();
    let mut evals: Vec<SecureField> = data.first_layer_evals.clone();
    assert_eq!(positions.len(), evals.len());
    let mut layer_maps: Vec<HashMap<usize, (SecureField, SecureField, SecureField)>> = Vec::new();
    let mut layers: Vec<LayerTree> = Vec::new();

    for layer in 0..n_layers {
        let alpha = alphas[layer];
        let fri_witness: &[SecureField] = if layer == 0 {
            &fp.first_layer.fri_witness
        } else {
            &fp.inner_layers[layer - 1].fri_witness
        };
        let mut wit = fri_witness.iter().copied();
        let mut map = HashMap::new();
        // The decommit positions (BOTH coset leaves) + leaf values, in sorted order.
        let mut dec_positions: Vec<usize> = Vec::new();
        let mut dec_leaf: HashMap<usize, SecureField> = HashMap::new();
        let mut next_pos = Vec::new();
        let mut next_ev = Vec::new();
        let mut i = 0;
        while i < positions.len() {
            let start = (positions[i] >> 1) << 1;
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
            dec_positions.push(start);
            dec_positions.push(start + 1);
            dec_leaf.insert(start, e0);
            dec_leaf.insert(start + 1, e1);
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

        // Build the layer's Merkle node map (sorted positions for the witness order).
        let height = first_log - layer as u32;
        let root: Hash8 = if layer == 0 {
            fp.first_layer.commitment.0
        } else {
            fp.inner_layers[layer - 1].commitment.0
        };
        let hash_witness: Vec<Hash8> = if layer == 0 {
            fp.first_layer.decommitment.hash_witness.iter().map(|h| h.0).collect()
        } else {
            fp.inner_layers[layer - 1].decommitment.hash_witness.iter().map(|h| h.0).collect()
        };
        let leaf_vals: Vec<SecureField> = dec_positions.iter().map(|p| dec_leaf[p]).collect();
        let node_map = decommit_node_map(height, root, &dec_positions, &leaf_vals, &hash_witness);
        layers.push(LayerTree { height, root, node_map });

        positions = next_pos;
        evals = next_ev;
    }

    // Per-query fold records (follow each original query down the layers).
    let per_query: Vec<Vec<FoldRec>> = data
        .query_positions
        .iter()
        .map(|&q0| {
            let mut pos = q0;
            (0..n_layers)
                .map(|layer| {
                    let sub = pos >> 1;
                    let (e0, e1, folded) = layer_maps[layer][&sub];
                    let twid = if layer == 0 {
                        point_at(&line_cosets[0], pos >> 1).y.inverse()
                    } else {
                        point_at(&line_cosets[layer - 1], pos & !1).x.inverse()
                    };
                    let rec = FoldRec { layer, k: sub, e0, e1, bit: (pos & 1) as u32, twid, folded };
                    pos = sub;
                    rec
                })
                .collect()
        })
        .collect();

    FriData { n_layers, layers, per_query, last_layer_const }
}

fn fold_step(f_a: SecureField, f_b: SecureField, alpha: SecureField, twid: BaseField) -> SecureField {
    (f_a + f_b) + alpha * ((f_a - f_b) * twid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Streamed coset decommit + co-located fold (one perm/row).
// ─────────────────────────────────────────────────────────────────────────────

// Main columns: perm, st[16], chunk[8], sib[8], bit, mux[8], lh[8], fold_bit,
// mux_fold[4], twid[4], alpha_sel[4], scaled[4], prod[4], folded[4], carry[4],
// alpha_lat[14*4].
const N_FRI_LAYERS: usize = 14;
const FOLD_QM31: usize = 6; // mux_fold, twid, alpha_sel, scaled, prod, folded
const N_MAIN_COLS: usize = N_PERM_COLS + N_STATE + 8 + 8 + 1 + 8 + 8
    + 1
    + FOLD_QM31 * SECURE_EXTENSION_DEGREE
    + SECURE_EXTENSION_DEGREE // carry
    + N_FRI_LAYERS * SECURE_EXTENSION_DEGREE; // alpha_lat

const NOT_LAST: &str = "fd_not_last";
const M_SPONGE: &str = "fd_m_sponge";
const M_MERGE: &str = "fd_m_merge";
const M_NODE: &str = "fd_m_node";
const M_ROOT: &str = "fd_m_root";
const ZERO_ST: &str = "fd_zero_st";
const HASH_LINK: &str = "fd_hash_link";
fn root_id(j: usize) -> String {
    format!("fd_root_{j}")
}
fn is_layer_id(l: usize) -> String {
    format!("fd_is_layer_{l}")
}

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<PreProcessedColumnId> =
        [NOT_LAST, M_SPONGE, M_MERGE, M_NODE, M_ROOT, ZERO_ST, HASH_LINK]
            .into_iter()
            .map(|id| PreProcessedColumnId { id: id.to_string() })
            .collect();
    for j in 0..8 {
        ids.push(PreProcessedColumnId { id: root_id(j) });
    }
    for l in 0..N_FRI_LAYERS {
        ids.push(PreProcessedColumnId { id: is_layer_id(l) });
    }
    ids
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

#[derive(Clone)]
struct FriDecommitEval {
    log_n_rows: u32,
    last_layer_const: SecureField,
}

impl FrameworkEval for FriDecommitEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let lift = |f: E::F| -> E::EF { E::combine_ef([f, E::F::zero(), E::F::zero(), E::F::zero()]) };
        let pre = |eval: &mut E, id: &str| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_string() })
        };
        // Preprocessed (registration order).
        let not_last = pre(&mut eval, NOT_LAST);
        let m_sponge = pre(&mut eval, M_SPONGE);
        let m_merge = pre(&mut eval, M_MERGE);
        let m_node = pre(&mut eval, M_NODE);
        let m_root = pre(&mut eval, M_ROOT);
        let zero_st = pre(&mut eval, ZERO_ST);
        let hash_link = pre(&mut eval, HASH_LINK);
        let root: [E::F; 8] =
            std::array::from_fn(|j| eval.get_preprocessed_column(PreProcessedColumnId { id: root_id(j) }));
        let is_layer: [E::F; N_FRI_LAYERS] =
            std::array::from_fn(|l| eval.get_preprocessed_column(PreProcessedColumnId { id: is_layer_id(l) }));

        // Main (cursor order = fill order).
        let (init, out) = eval_permutation(&mut eval);
        let st: [[E::F; 2]; N_STATE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let st_cur = |j: usize| st[j][0].clone();
        let st_next = |j: usize| st[j][1].clone();
        let chunk: [[E::F; 2]; 8] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let bit = eval.next_trace_mask();
        let mux: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let lh: [[E::F; 3]; 8] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [-2, -1, 0]));
        let fold_bit = eval.next_trace_mask();
        let read4 = |eval: &mut E| -> E::EF { E::combine_ef(std::array::from_fn(|_| eval.next_trace_mask())) };
        let mux_fold = read4(&mut eval);
        let twid = read4(&mut eval);
        let alpha_sel = read4(&mut eval);
        let scaled = read4(&mut eval);
        let prod = read4(&mut eval);
        let folded = read4(&mut eval);
        let carry: [[E::F; 2]; SECURE_EXTENSION_DEGREE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let carry_cur = E::combine_ef(std::array::from_fn(|i| carry[i][0].clone()));
        let carry_next = E::combine_ef(std::array::from_fn(|i| carry[i][1].clone()));
        let alpha_lat: [[[E::F; 2]; SECURE_EXTENSION_DEGREE]; N_FRI_LAYERS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1])));

        // ── Decommit constraints (the recursion_decommit_scale gadget + a MERGE) ──
        for j in 0..N_STATE {
            eval.add_constraint(zero_st.clone() * st_cur(j));
        }
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        for j in 0..8 {
            eval.add_constraint(mux[j].clone() - bit.clone() * (sib[j].clone() - st_cur(j)));
        }
        // Leaf sponge: rate += chunk, capacity carried; bind the leaf hash lh = out.
        for j in 0..8 {
            eval.add_constraint(m_sponge.clone() * (init[j].clone() - st_cur(j) - chunk[j][0].clone()));
            eval.add_constraint(m_sponge.clone() * (init[8 + j].clone() - st_cur(8 + j)));
            eval.add_constraint(m_sponge.clone() * (lh[j][2].clone() - out[j].clone()));
        }
        // Merge: hash_children(h0=lh@[-2], h1=lh@[-1]); e0(2k) left, e1(2k+1) right.
        for j in 0..8 {
            eval.add_constraint(m_merge.clone() * (init[j].clone() - lh[j][0].clone()));
            eval.add_constraint(m_merge.clone() * (init[8 + j].clone() - lh[j][1].clone()));
        }
        // hash_children climb: bit-ordered (cur, sib) via the witnessed mux.
        for j in 0..8 {
            let left = st_cur(j) + mux[j].clone();
            let right = sib[j].clone() - mux[j].clone();
            eval.add_constraint(m_node.clone() * (init[j].clone() - left));
            eval.add_constraint(m_node.clone() * (init[8 + j].clone() - right));
        }
        // State threading (rate) + root pin.
        for j in 0..8 {
            eval.add_constraint(hash_link.clone() * (st_next(j) - out[j].clone()));
            eval.add_constraint(m_root.clone() * (out[j].clone() - root[j].clone()));
        }

        // ── Fold step (rides every row; conditional checks gated) ──
        // e0 = this row's leaf chunk; e1 = the next row's (= the e1 sponge).
        let e0 = E::combine_ef(std::array::from_fn(|i| chunk[i][0].clone()));
        let e1 = E::combine_ef(std::array::from_fn(|i| chunk[i][1].clone()));
        let is_fold: E::F = is_layer.iter().fold(E::F::zero(), |a, b| a + b.clone());
        let is_run: E::F = is_layer[1..].iter().fold(E::F::zero(), |a, b| a + b.clone());
        // fold_bit boolean + running mux = fold_bit·(e1−e0).
        eval.add_constraint(fold_bit.clone() * (fold_bit.clone() - one.clone()));
        eval.add_constraint(mux_fold.clone() - lift(fold_bit.clone()) * (e1.clone() - e0.clone()));
        let running = e0.clone() + mux_fold.clone();
        // alpha_sel = Σ is_layer[L]·alpha_lat[L]; scaled = (e0−e1)·twid; prod, folded.
        let mut sel = E::EF::zero();
        for (l, isl) in is_layer.iter().enumerate() {
            let a = E::combine_ef(std::array::from_fn(|i| alpha_lat[l][i][0].clone()));
            sel += lift(isl.clone()) * a;
        }
        eval.add_constraint(alpha_sel.clone() - sel);
        eval.add_constraint(scaled.clone() - (e0.clone() - e1.clone()) * twid.clone());
        eval.add_constraint(prod.clone() - alpha_sel.clone() * scaled.clone());
        eval.add_constraint(folded.clone() - (e0.clone() + e1.clone() + prod.clone()));
        // Carry latch: carry[next] = is_fold ? folded : carry[cur] (cycle closed by fill).
        eval.add_constraint(carry_next - carry_cur.clone() - lift(is_fold.clone()) * (folded.clone() - carry_cur.clone()));
        // Cross-layer chain: at L>0 the running leaf == carry (= folded[L−1]).
        eval.add_constraint(lift(is_run) * (running - carry_cur));
        // Last layer (L=13): folded == the degree-0 last-layer constant.
        eval.add_constraint(lift(is_layer[N_FRI_LAYERS - 1].clone()) * (folded - E::EF::from(self.last_layer_const)));
        // Alpha latches held constant.
        for al in &alpha_lat {
            for coord in al {
                eval.add_constraint(not_last.clone() * (coord[1].clone() - coord[0].clone()));
            }
        }
        eval
    }
}

// ── Host stream + trace fill ──────────────────────────────────────────────────

#[derive(Clone)]
struct Row {
    init: [BaseField; N_STATE],
    st_cur: [BaseField; N_STATE],
    chunk: [BaseField; 8],
    sib: [BaseField; 8],
    bit: u32,
    lh: [BaseField; 8],
    root: [BaseField; 8],
    layer: Option<usize>, // Some on a fold (e0-sponge) row
    fold: Option<FoldRec>,
    m_sponge: bool,
    m_merge: bool,
    m_node: bool,
    m_root: bool,
    zero_st: bool,
    hash_link: bool,
}
fn zrow() -> Row {
    let zb = BaseField::zero();
    Row {
        init: [zb; N_STATE], st_cur: [zb; N_STATE], chunk: [zb; 8], sib: [zb; 8], bit: 0,
        lh: [zb; 8], root: [zb; 8], layer: None, fold: None,
        m_sponge: false, m_merge: false, m_node: false, m_root: false, zero_st: false, hash_link: false,
    }
}

fn sponge_row(value: SecureField, root: Hash8, layer: Option<usize>, fold: Option<FoldRec>) -> (Row, Hash8) {
    let zb = BaseField::zero();
    let mut chunk = [zb; 8];
    let coords = value.to_m31_array();
    chunk[..4].copy_from_slice(&coords);
    chunk[4] = BaseField::one(); // partial-rate finalize pad for width 4
    let mut init = [zb; N_STATE];
    init[..8].copy_from_slice(&chunk[..8]);
    let mut o = init;
    permute(&mut o);
    let h: Hash8 = std::array::from_fn(|j| o[j]);
    let mut r = zrow();
    r.init = init;
    r.chunk = chunk;
    r.lh = h;
    r.zero_st = true;
    r.m_sponge = true;
    r.root = root;
    r.layer = layer;
    r.fold = fold;
    (r, h)
}

/// Lay out the per-(query,layer) FRI coset decommit + co-located fold as rows.
fn resolve(fri: &FriData) -> Vec<Row> {
    let zb = BaseField::zero();
    let mut rows: Vec<Row> = Vec::new();
    for recs in &fri.per_query {
        for rec in recs {
            let lt = &fri.layers[rec.layer];
            let k = rec.k;
            let pos0 = 2 * k;
            // The two coset leaf hashes (cross-checked against the node map).
            let (r0, h0) = sponge_row(rec.e0, lt.root, Some(rec.layer), Some(*rec));
            let (r1, h1) = sponge_row(rec.e1, lt.root, None, None);
            debug_assert_eq!(h0, lt.node_map[0][&pos0]);
            debug_assert_eq!(h1, lt.node_map[0][&(pos0 + 1)]);
            rows.push(r0);
            rows.push(r1);
            // Merge: hash_children(h0, h1) → parent@(level 1, k).
            let mut init = [zb; N_STATE];
            init[..8].copy_from_slice(&h0);
            init[8..].copy_from_slice(&h1);
            let mut o = init;
            permute(&mut o);
            let mut state: Hash8 = std::array::from_fn(|j| o[j]);
            debug_assert_eq!(state, lt.node_map[1][&k]);
            let mut mr = zrow();
            mr.init = init;
            mr.root = lt.root;
            mr.m_merge = true;
            mr.hash_link = true;
            rows.push(mr);
            // Climb from level 1 (position k) to the root.
            for lev in 1..lt.height as usize {
                let node_idx = k >> (lev - 1);
                let bit = (node_idx & 1) as u32;
                let sib = lt.node_map[lev][&(node_idx ^ 1)];
                let cur = state;
                let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
                let mut init = [zb; N_STATE];
                init[..8].copy_from_slice(&left);
                init[8..].copy_from_slice(&right);
                let mut o = init;
                permute(&mut o);
                state = std::array::from_fn(|j| o[j]);
                let is_root = lev + 1 == lt.height as usize;
                let mut nr = zrow();
                nr.init = init;
                nr.st_cur[..8].copy_from_slice(&cur);
                nr.sib = sib;
                nr.bit = bit;
                nr.root = lt.root;
                nr.m_node = true;
                nr.m_root = is_root;
                nr.hash_link = !is_root;
                rows.push(nr);
            }
            debug_assert_eq!(state, lt.root, "coset climb must reach the layer root");
        }
    }
    rows
}

struct Trace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    Leaf,   // bump a coset leaf value (breaks the leaf hash + the fold)
    Sib,    // bump a climb sibling
    Folded, // bump a folded output (breaks the chain / last-layer check)
}

fn gen_trace(fri: &FriData, tamper: Tamper) -> Trace {
    let zb = BaseField::zero();
    let z = SecureField::zero();
    let mut rows = resolve(fri);
    let n_used = rows.len();
    let log_size = (n_used as u32).next_power_of_two().trailing_zeros().max(1);
    let n = 1usize << log_size;
    rows.resize(n, zrow());

    if let Tamper::Leaf = tamper {
        let r = rows.iter().position(|f| f.layer.is_some()).unwrap();
        rows[r].chunk[0] += BaseField::one();
    }
    if let Tamper::Sib = tamper {
        let r = rows.iter().position(|f| f.m_node).unwrap();
        rows[r].sib[0] += BaseField::one();
    }

    let alphas: Vec<SecureField> = {
        // fold_alphas in layer order, recovered from any query's records.
        let mut a = vec![z; N_FRI_LAYERS];
        for rec in &fri.per_query[0] {
            // alpha_L is implied by folded = e0+e1+alpha*(e0-e1)*twid.
            let d = (rec.e0 - rec.e1) * rec.twid;
            a[rec.layer] = if d == z { z } else { (rec.folded - (rec.e0 + rec.e1)) * d.inverse() };
        }
        a
    };

    // Fold columns per row (leaf_val[r] = combine(chunk[r][0..4])).
    let leaf_val: Vec<SecureField> = rows
        .iter()
        .map(|r| SecureField::from_m31_array([r.chunk[0], r.chunk[1], r.chunk[2], r.chunk[3]]))
        .collect();
    let mut fold_bit = vec![zb; n];
    let mut mux_fold = vec![z; n];
    let mut twid = vec![z; n];
    let mut alpha_sel = vec![z; n];
    let mut scaled = vec![z; n];
    let mut prod = vec![z; n];
    let mut folded = vec![z; n];
    for r in 0..n {
        let e0 = leaf_val[r];
        let e1 = leaf_val[(r + 1) % n];
        if let Some(rec) = rows[r].fold {
            fold_bit[r] = BaseField::from(rec.bit);
            mux_fold[r] = SecureField::from(BaseField::from(rec.bit)) * (e1 - e0);
            twid[r] = SecureField::from(rec.twid);
            alpha_sel[r] = alphas[rec.layer];
            scaled[r] = (e0 - e1) * twid[r];
            prod[r] = alpha_sel[r] * scaled[r];
            folded[r] = e0 + e1 + prod[r];
            debug_assert_eq!(e0, rec.e0, "fold-row e0 must equal the leaf chunk");
            debug_assert_eq!(e1, rec.e1, "fold-row e1 must equal the next-row leaf chunk");
            debug_assert_eq!(folded[r], rec.folded, "host fold must match reconstruction");
        } else {
            folded[r] = e0 + e1; // dummy-consistent (prod = 0)
        }
    }
    if let Tamper::Folded = tamper {
        let r = rows.iter().position(|f| f.fold.is_some()).unwrap();
        folded[r] += SecureField::one();
    }
    // Carry forward, cycle closed: seed with the last query's folded[13].
    let last_folded = fri.per_query.last().unwrap().last().unwrap().folded;
    let mut carry = vec![z; n];
    let mut cur = last_folded;
    for r in 0..n {
        carry[r] = cur;
        if rows[r].fold.is_some() {
            cur = folded[r];
        }
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |logical: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in logical.into_iter().enumerate() {
            c.set(storage_index(i, log_size), v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };
    // Preprocessed (registration order).
    let bcol = |sel: &dyn Fn(&Row) -> bool| -> Vec<BaseField> {
        rows.iter().map(|f| if sel(f) { BaseField::one() } else { zb }).collect()
    };
    let mut pre_b: Vec<Vec<BaseField>> = vec![
        (0..n).map(|i| if i + 1 < n { BaseField::one() } else { zb }).collect(), // not_last
        bcol(&|f| f.m_sponge),
        bcol(&|f| f.m_merge),
        bcol(&|f| f.m_node),
        bcol(&|f| f.m_root),
        bcol(&|f| f.zero_st),
        bcol(&|f| f.hash_link),
    ];
    for j in 0..8 {
        pre_b.push(rows.iter().map(|f| f.root[j]).collect());
    }
    for l in 0..N_FRI_LAYERS {
        pre_b.push(rows.iter().map(|f| if f.layer == Some(l) { BaseField::one() } else { zb }).collect());
    }
    let preprocessed: Vec<_> = pre_b.into_iter().map(wrap).collect();

    // Main (cursor order).
    let mut main_logical: Vec<Vec<BaseField>> = (0..N_MAIN_COLS).map(|_| Vec::with_capacity(n)).collect();
    for (r, f) in rows.iter().enumerate() {
        let mux: [BaseField; 8] = std::array::from_fn(|j| BaseField::from(f.bit) * (f.sib[j] - f.st_cur[j]));
        let mut row: Vec<BaseField> = record_permutation(f.init);
        row.extend_from_slice(&f.st_cur);
        row.extend_from_slice(&f.chunk);
        row.extend_from_slice(&f.sib);
        row.push(BaseField::from(f.bit));
        row.extend_from_slice(&mux);
        row.extend_from_slice(&f.lh);
        row.push(fold_bit[r]);
        for v in [mux_fold[r], twid[r], alpha_sel[r], scaled[r], prod[r], folded[r], carry[r]] {
            row.extend_from_slice(&v.to_m31_array());
        }
        for l in 0..N_FRI_LAYERS {
            row.extend_from_slice(&alphas[l].to_m31_array());
        }
        debug_assert_eq!(row.len(), N_MAIN_COLS);
        for (c, v) in row.into_iter().enumerate() {
            main_logical[c].push(v);
        }
    }
    let main: Vec<_> = main_logical.into_iter().map(wrap).collect();

    Trace { preprocessed, main, log_size }
}

fn eval_of(fri: &FriData, log_size: u32) -> FriDecommitEval {
    FriDecommitEval { log_n_rows: log_size, last_layer_const: fri.last_layer_const }
}

fn prove_and_verify(fri: &FriData, tamper: Tamper) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(fri, tamper);
    let log_size = trace.log_size;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor).circle_domain().half_coset,
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.preprocessed);
    tb.commit(channel);
    let mut tb = cs.tree_builder();
    tb.extend_evals(trace.main);
    tb.commit(channel);

    let mut alloc = TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids());
    let component =
        FrameworkComponent::<FriDecommitEval>::new(&mut alloc, eval_of(fri, log_size), SecureField::zero());
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;
    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof).map_err(|e| format!("verify: {e:?}"))
}

/// FAST: the streamed FRI-layer decommit + co-located fold trace satisfies the AIR.
#[test]
#[ignore = "heavy: prove_canonical builds a real 31-component segment (~30s release)"]
fn fri_decommit_air_satisfied() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let fri = reconstruct(&proof, &data);
    let trace = gen_trace(&fri, Tamper::None);
    let log_size = trace.log_size;
    let pre: Vec<Vec<M31>> = trace.preprocessed.iter().map(|e| e.values.to_cpu()).collect();
    let main: Vec<Vec<M31>> = trace.main.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> =
        TreeVec::new(vec![pre.iter().collect(), main.iter().collect(), vec![]]);
    assert_constraints_on_trace(&tv, log_size, |e| { eval_of(&fri, log_size).evaluate(e); }, SecureField::zero());
    eprintln!(
        "fri_decommit_air_satisfied: {} layers, {} queries → {} streamed rows (log {log_size}); each \
         coset's two leaves re-hash to the layer root + the co-located fold chains via the carry latch.",
        fri.n_layers, fri.per_query.len(),
        fri.per_query.iter().flatten().map(|r| 2 + 1 + (fri.layers[r.layer].height as usize - 1)).sum::<usize>(),
    );
}

/// THE GATE: the FRI-layer decommit + co-located fold proves+verifies; a tampered
/// leaf / sibling / fold output is each rejected.
#[test]
#[ignore = "heavy: real-segment FRI-layer decommit + fold prove+verify (release)"]
fn fri_decommit_gate() {
    let (proof, sn) = canonical_segment();
    let data = extract_recursion_data(&proof, &sn);
    let fri = reconstruct(&proof, &data);

    prove_and_verify(&fri, Tamper::None).expect("honest FRI-layer decommit + fold");
    assert!(prove_and_verify(&fri, Tamper::Leaf).is_err(), "a tampered coset leaf must be rejected");
    assert!(prove_and_verify(&fri, Tamper::Sib).is_err(), "a tampered climb sibling must be rejected");
    assert!(prove_and_verify(&fri, Tamper::Folded).is_err(), "a tampered fold output must be rejected");

    eprintln!(
        "fri_decommit_gate GREEN: the REAL {}-layer FRI fold chain ({} queries) folds inputs that are \
         each a decommitted leaf of the layer's Merkle tree (re-hashed to the layer root, host twiddle \
         forced by consistency, cross-layer carry latch) — proves+verifies through the lifted \
         Poseidon2-M31 protocol at degree ≤ 2; tampered leaf / sibling / fold each rejected.",
        fri.n_layers, fri.per_query.len(),
    );
}
