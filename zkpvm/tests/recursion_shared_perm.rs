//! Recursion build P5.3 — **the shared-perm-block crux (steps 2+3 foundation).**
//!
//! The channel transcript replay (`join_assembly` / `recursion_child_assembly`)
//! already runs ONE `eval_permutation` per row, streaming the Fiat-Shamir
//! transcript across rows with the digest chained by a latch. The proven
//! multi-tree Merkle decommit (`merkle_decommit_trees`) instead runs MANY perms
//! per row (a leaf sponge + every `hash_children` level inline). To fold the
//! decommit into the SAME uniform component as the channel — the architectural
//! crux of the full per-child verifier — the decommit must also become ONE perm
//! per row, so a single row-type selector can choose between a channel-transcript
//! perm and a Merkle `hash_children` perm.
//!
//! This spike proves that unification mechanism at small (fast) scale:
//!
//!   * **Streamed Merkle decommit.** A real small Poseidon2-M31 proof's main
//!     trace-tree decommitment paths are verified one perm PER ROW — the leaf
//!     sponge (`update_leaf` absorbs + the padded `finalize`) and each
//!     `hash_children` level are each their own row, the 16-wide sponge/hash
//!     state threaded row→row via a `[0,1]` latch on dedicated `st` columns
//!     (exactly the channel's digest-chain mechanism). The recomputed root is
//!     pinned to the proof's real commitment, so the in-AIR re-hash IS a real
//!     decommit verification (the `merkle_decommit_trees` soundness argument).
//!   * **Row-type selector.** Preprocessed `is_tr` / `m_abs` / `m_final` /
//!     `m_node` columns gate the channel constraints vs the Merkle constraints so
//!     both regions ride ONE `eval_permutation`/row. The schedule (which row does
//!     which step) is FIXED given the tree shapes + query count — segment-
//!     invariant, hence preprocessed, exactly like the streamed-embed routing.
//!   * **Degree ≤ 2.** The bit-driven `hash_children` child ordering would be
//!     degree 3 (`m_node · bit · sib`); a witnessed `mux = bit·(sib − cur)` lowers
//!     the select to degree 2 (`left = cur + mux`, `right = sib − mux`).
//!
//! A minimal absorb-style transcript region (digest chained across rows, capacity
//! pinned 0) precedes the merkle region — enough to exercise the selector
//! isolation (its gated constraints must NOT fire on merkle rows, and vice
//! versa); the full channel constraints are already proven and gate identically
//! in the integration.
//!
//! `assert_constraints_on_trace` checks only ZERO-ness, NOT the degree bound (a
//! degree-3 slip surfaces only as a FRI failure at prove), so the milestone is the
//! PROVE; the assert is the fast value-bug gate run first.
//!
//! GREEN GATE: a real proof's main trace-tree decommit re-hashes to its real root
//! in a STREAMED (one-perm/row) form sharing the perm slot with a transcript
//! region, proves+verifies through the lifted Poseidon2-M31 protocol; a tampered
//! leaf value, a tampered sibling, and a tampered transcript value are each
//! rejected.
//!
//! Run: `cargo test -p zkpvm --features poseidon2-channel --test \
//!     recursion_shared_perm -- --nocapture`

#![cfg(feature = "poseidon2-channel")]

mod recursion_common;

use std::collections::HashMap;

use num_traits::{One, Zero};
use recursion_common::{
    N_PERM_COLS, N_STATE, P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel,
    eval_permutation, hash_children_m31, mobile_config, permute, record_permutation,
};
use stwo::core::air::{Component, Components};
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{COMPOSITION_LOG_SPLIT, verify};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
    assert_constraints_on_trace, preprocessed_columns::PreProcessedColumnId,
};

// ─────────────────────────────────────────────────────────────────────────────
// A representative inner proof (the decommit target) — mirrors merkle_decommit_trees.
// ─────────────────────────────────────────────────────────────────────────────

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
const HEIGHT: u32 = 7; // lifting_log_size for the inner proof (probe-confirmed)

fn inner_trace() -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << INNER_LOG;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..INNER_MAIN_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for row in 0..n {
        let a = SecureFieldRow::a(row);
        let b = SecureFieldRow::b(row);
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

use stwo::core::fields::qm31::SecureField;
struct SecureFieldRow;
impl SecureFieldRow {
    fn a(row: usize) -> SecureField {
        SecureField::from_m31_array([
            BaseField::from(row as u32 + 1),
            BaseField::from(row as u32 + 7),
            BaseField::from(row as u32 + 13),
            BaseField::from(row as u32 + 23),
        ])
    }
    fn b(row: usize) -> SecureField {
        SecureField::from_m31_array([
            BaseField::from(row as u32 + 2),
            BaseField::from(row as u32 + 3),
            BaseField::from(row as u32 + 5),
            BaseField::from(row as u32 + 11),
        ])
    }
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

const N_COMPOSITION_COLS: usize = 8;

/// Replay the verifier transcript to recover the REAL drawn query positions.
fn real_query_positions(inner: &InnerProof, config: PcsConfig) -> Vec<usize> {
    let component = &inner.component;
    let proof = &inner.proof;
    let channel = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], channel);
    vs.commit(proof.commitments[1], &sizes[1], channel);

    let components = Components {
        components: vec![component as &dyn Component],
        n_preprocessed_columns: 0,
    };
    let split = components.composition_log_degree_bound() - COMPOSITION_LOG_SPLIT;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split + config.fri_config.log_blowup_factor).unwrap();
    let max_log_degree_bound = lifting_log_size - config.fri_config.log_blowup_factor;

    let _ = channel.draw_secure_felt();
    vs.commit(
        *proof.commitments.last().unwrap(),
        &[max_log_degree_bound; N_COMPOSITION_COLS],
        channel,
    );
    let _ = CirclePoint::<SecureField>::get_random_point(channel);
    channel.mix_felts(&proof.sampled_values.clone().flatten_cols());
    let _ = channel.draw_secure_felt();
    let bound = CirclePolyDegreeBound::new(lifting_log_size - config.fri_config.log_blowup_factor);
    let mut fri_verifier = FriVerifier::<P2MerkleChannel>::commit(
        channel,
        config.fri_config,
        proof.fri_proof.clone(),
        bound,
    )
    .expect("fri commit");
    assert!(channel.verify_pow_nonce(config.pow_bits, proof.proof_of_work));
    channel.mix_u64(proof.proof_of_work);
    fri_verifier.sample_query_positions(channel)
}

// ── Host: replay MerkleVerifierLifted::verify into a full node map ─────────────

type Hash8 = [BaseField; 8];

fn sponge_leaf(row: &[BaseField]) -> Hash8 {
    let mut h = P2MerkleHasher::default();
    h.update_leaf(row);
    h.finalize().0
}

struct DecommitPath {
    leaf_vals: Vec<BaseField>,
    bits: Vec<u32>,
    sibs: Vec<Hash8>,
}

fn decommit_node_map(
    height: u32,
    root: Hash8,
    query_positions: &[usize],
    queried_values: &[Vec<BaseField>],
    hash_witness: &[P2Hash],
) -> Vec<HashMap<usize, Hash8>> {
    let n_cols = queried_values.len();
    let mut node_map: Vec<HashMap<usize, Hash8>> = vec![HashMap::new(); (height + 1) as usize];
    let mut layer: Vec<(usize, Hash8)> = Vec::new();
    for (i, &pos) in query_positions.iter().enumerate() {
        let row: Vec<BaseField> = (0..n_cols).map(|c| queried_values[c][i]).collect();
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
                let w = witness.next().expect("witness too short").0;
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
    assert_eq!(
        layer[0].1, root,
        "recomputed root must equal the commitment"
    );
    node_map
}

fn extract_path(
    node_map: &[HashMap<usize, Hash8>],
    height: u32,
    pos: usize,
    leaf_vals: Vec<BaseField>,
) -> DecommitPath {
    let mut bits = Vec::with_capacity(height as usize);
    let mut sibs = Vec::with_capacity(height as usize);
    for level in 0..height as usize {
        let node_idx = pos >> level;
        bits.push((node_idx & 1) as u32);
        sibs.push(node_map[level][&(node_idx ^ 1)]);
    }
    DecommitPath {
        leaf_vals,
        bits,
        sibs,
    }
}

fn tree_paths(
    inner: &InnerProof,
    tree_index: usize,
    n_leaf_cols: usize,
    height: u32,
    query_positions: &[usize],
) -> (Vec<DecommitPath>, Hash8) {
    let proof = &inner.proof;
    let queried = &proof.queried_values[tree_index];
    let witness = &proof.decommitments[tree_index].hash_witness;
    let root = proof.commitments[tree_index].0;
    assert_eq!(queried.len(), n_leaf_cols);
    let node_map = decommit_node_map(height, root, query_positions, queried, witness);
    let paths = query_positions
        .iter()
        .enumerate()
        .map(|(i, &pos)| {
            let row: Vec<BaseField> = (0..n_leaf_cols).map(|c| queried[c][i]).collect();
            extract_path(&node_map, height, pos, row)
        })
        .collect();
    (paths, root)
}

// ─────────────────────────────────────────────────────────────────────────────
// The streamed shared-perm AIR: one eval_permutation/row, row-type selector.
// ─────────────────────────────────────────────────────────────────────────────

// Preprocessed selector ids (registration / read / fill order).
const IS_TR: &str = "sp_is_tr";
const M_ABS: &str = "sp_m_abs";
const M_FINAL: &str = "sp_m_final";
const M_NODE: &str = "sp_m_node";
const M_ROOT: &str = "sp_m_root";
const ZERO_ST: &str = "sp_zero_st"; // st_cur := 0 (transcript row 0 + each leaf's first absorb)
const HASH_LINK: &str = "sp_hash_link"; // out[0..8] threads to next row's st_cur[0..8]
const CAP_FWD: &str = "sp_cap_fwd"; // out[8..16] threads to next row's st_cur[8..16]

fn preproc_ids() -> Vec<PreProcessedColumnId> {
    [
        IS_TR, M_ABS, M_FINAL, M_NODE, M_ROOT, ZERO_ST, HASH_LINK, CAP_FWD,
    ]
    .into_iter()
    .map(|id| PreProcessedColumnId { id: id.to_string() })
    .collect()
}

// Main columns per row: perm (init+sboxes) then st[16], sib[8], bit, mux[8], leaf[8].
const N_MAIN_COLS: usize = N_PERM_COLS + 16 + 8 + 1 + 8 + 8;

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

#[derive(Clone)]
struct SharedPermEval {
    log_n_rows: u32,
    root: Hash8,
}

impl FrameworkEval for SharedPermEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let pre = |eval: &mut E, id: &str| {
            eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_string() })
        };
        // Preprocessed reads — EXACT registration order (cursor-based).
        let is_tr = pre(&mut eval, IS_TR);
        let m_abs = pre(&mut eval, M_ABS);
        let m_final = pre(&mut eval, M_FINAL);
        let m_node = pre(&mut eval, M_NODE);
        let m_root = pre(&mut eval, M_ROOT);
        let zero_st = pre(&mut eval, ZERO_ST);
        let hash_link = pre(&mut eval, HASH_LINK);
        let cap_fwd = pre(&mut eval, CAP_FWD);

        // The shared permutation (always constrained: out == permute(init)).
        let (init, out) = eval_permutation(&mut eval);

        // Carried 16-wide state, read at [cur, next]: st_cur drives this row's
        // perm input; st_next (= next row's st_cur) is threaded to this row's out.
        let st: [[E::F; 2]; N_STATE] =
            std::array::from_fn(|_| eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]));
        let st_cur = |j: usize| st[j][0].clone();
        let st_next = |j: usize| st[j][1].clone();

        let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let bit = eval.next_trace_mask();
        let mux: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let leaf: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());

        // ── Fresh-sponge / initial-digest zeroing. ──
        for j in 0..N_STATE {
            eval.add_constraint(zero_st.clone() * st_cur(j));
        }

        // ── bit booleanity + the degree-lowering mux = bit·(sib − cur). ──
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        for j in 0..8 {
            eval.add_constraint(mux[j].clone() - bit.clone() * (sib[j].clone() - st_cur(j)));
        }

        // ── Transcript row: absorb-style squeeze, init = digest ‖ 0. ──
        for j in 0..8 {
            eval.add_constraint(is_tr.clone() * (init[j].clone() - st_cur(j)));
            eval.add_constraint(is_tr.clone() * init[8 + j].clone());
        }

        // ── Leaf absorb: rate += leaf chunk, capacity carried. ──
        for j in 0..8 {
            eval.add_constraint(m_abs.clone() * (init[j].clone() - st_cur(j) - leaf[j].clone()));
            eval.add_constraint(m_abs.clone() * (init[8 + j].clone() - st_cur(8 + j)));
        }

        // ── Finalize: rate[0] += 1 (the [1,0,…] pad), capacity carried. ──
        eval.add_constraint(m_final.clone() * (init[0].clone() - st_cur(0) - one.clone()));
        for j in 1..8 {
            eval.add_constraint(m_final.clone() * (init[j].clone() - st_cur(j)));
        }
        for j in 0..8 {
            eval.add_constraint(m_final.clone() * (init[8 + j].clone() - st_cur(8 + j)));
        }

        // ── hash_children: bit-ordered (cur, sib) via the witnessed mux. ──
        for j in 0..8 {
            let left = st_cur(j) + mux[j].clone(); // bit=0 → cur, bit=1 → sib
            let right = sib[j].clone() - mux[j].clone(); // bit=0 → sib, bit=1 → cur
            eval.add_constraint(m_node.clone() * (init[j].clone() - left));
            eval.add_constraint(m_node.clone() * (init[8 + j].clone() - right));
        }

        // ── State threading: hash (rate) always within a path; capacity only
        //    across sponge continuations. ──
        for j in 0..8 {
            eval.add_constraint(hash_link.clone() * (st_next(j) - out[j].clone()));
            eval.add_constraint(cap_fwd.clone() * (st_next(8 + j) - out[8 + j].clone()));
        }

        // ── Pin the recomputed root at each path's last (root) node row. ──
        for j in 0..8 {
            eval.add_constraint(m_root.clone() * (out[j].clone() - E::F::from(self.root[j])));
        }

        eval
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host schedule + trace fill.
// ─────────────────────────────────────────────────────────────────────────────

/// One scheduled row (the fixed, segment-invariant "program").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    Transcript { first: bool, last: bool },
    Absorb { first: bool, chunk: usize },
    Final,
    Node { level: u32, root: bool },
    Pad,
}

/// Per-row resolved values fed to both the host fill and the preprocessed columns.
struct RowFill {
    init: [BaseField; N_STATE],
    st_cur: [BaseField; N_STATE],
    sib: [BaseField; 8],
    bit: u32,
    leaf: [BaseField; 8],
    is_tr: bool,
    m_abs: bool,
    m_final: bool,
    m_node: bool,
    m_root: bool,
    zero_st: bool,
    hash_link: bool,
    cap_fwd: bool,
}

/// Build the full row schedule: a short transcript region then the streamed
/// decommit of every path, then padding to `n` rows.
fn schedule(n_paths: usize, n_transcript: usize, height: u32, n_abs: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    for i in 0..n_transcript {
        steps.push(Step::Transcript {
            first: i == 0,
            last: i + 1 == n_transcript,
        });
    }
    for _ in 0..n_paths {
        for chunk in 0..n_abs {
            steps.push(Step::Absorb {
                first: chunk == 0,
                chunk,
            });
        }
        steps.push(Step::Final);
        for level in 0..height {
            steps.push(Step::Node {
                level,
                root: level + 1 == height,
            });
        }
    }
    steps
}

/// `hash_link`/`cap_fwd` for row `i`: whether this row's `out` threads forward.
fn links(steps: &[Step], i: usize) -> (bool, bool) {
    let cur = steps[i];
    let next = steps.get(i + 1).copied();
    let hash_link = match (cur, next) {
        // Transcript chains its digest to the next transcript row.
        (Step::Transcript { last: false, .. }, _) => true,
        // Within a path: absorb→absorb/final, final→node, node→node (not after root).
        (Step::Absorb { .. }, _) => true,
        (Step::Final, _) => true,
        (Step::Node { root: false, .. }, _) => true,
        _ => false,
    };
    // Capacity carries only while the sponge continues (absorb → absorb/final).
    let cap_fwd = matches!(
        (cur, next),
        (Step::Absorb { .. }, Some(Step::Absorb { .. })) | (Step::Absorb { .. }, Some(Step::Final))
    );
    (hash_link, cap_fwd)
}

fn resolve(steps: &[Step], paths: &[DecommitPath], n_abs: usize) -> Vec<RowFill> {
    let zb = BaseField::zero();
    let mut out = Vec::with_capacity(steps.len());
    // Path-walk state: the running 16-wide sponge/hash state (= previous out).
    let mut state = [zb; N_STATE];
    let mut path_idx = 0usize;
    for (i, &step) in steps.iter().enumerate() {
        let (hash_link, cap_fwd) = links(steps, i);
        let mut f = RowFill {
            init: [zb; N_STATE],
            st_cur: [zb; N_STATE],
            sib: [zb; 8],
            bit: 0,
            leaf: [zb; 8],
            is_tr: false,
            m_abs: false,
            m_final: false,
            m_node: false,
            m_root: false,
            zero_st: false,
            hash_link,
            cap_fwd,
        };
        match step {
            Step::Transcript { first, .. } => {
                f.is_tr = true;
                f.zero_st = first;
                let st_cur = if first { [zb; N_STATE] } else { state };
                f.st_cur = st_cur;
                let mut init = [zb; N_STATE];
                init[..8].copy_from_slice(&st_cur[..8]); // digest into rate, capacity 0
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o;
            }
            Step::Absorb { first, chunk } => {
                let p = &paths[path_idx];
                f.m_abs = true;
                f.zero_st = first;
                let st_cur = if first { [zb; N_STATE] } else { state };
                f.st_cur = st_cur;
                let mut leaf = [zb; 8];
                leaf.copy_from_slice(&p.leaf_vals[chunk * 8..chunk * 8 + 8]);
                f.leaf = leaf;
                let mut init = st_cur;
                for j in 0..8 {
                    init[j] += leaf[j];
                }
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o;
            }
            Step::Final => {
                f.m_final = true;
                f.st_cur = state;
                let mut init = state;
                init[0] += BaseField::one();
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o; // out[0..8] = the leaf hash
            }
            Step::Node { level, root } => {
                let p = &paths[path_idx];
                f.m_node = true;
                f.m_root = root;
                // cur = previous out[0..8] (leaf hash for level 0), capacity 0.
                let mut st_cur = [zb; N_STATE];
                st_cur[..8].copy_from_slice(&state[..8]);
                f.st_cur = st_cur;
                let bit = p.bits[level as usize];
                let sib = p.sibs[level as usize];
                f.bit = bit;
                f.sib = sib;
                let cur: [BaseField; 8] = std::array::from_fn(|j| st_cur[j]);
                let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
                let mut init = [zb; N_STATE];
                init[..8].copy_from_slice(&left);
                init[8..].copy_from_slice(&right);
                f.init = init;
                let mut o = init;
                permute(&mut o);
                state = o;
                if root {
                    path_idx += 1;
                    state = [zb; N_STATE];
                }
            }
            Step::Pad => {
                f.init = [zb; N_STATE];
                state = [zb; N_STATE];
            }
        }
        out.push(f);
    }
    let _ = n_abs;
    out
}

struct Trace {
    preprocessed: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    main: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    log_size: u32,
}

#[derive(Clone, Copy)]
enum Tamper {
    None,
    Leaf,       // bump a leaf value on an absorb row
    Sibling,    // bump a sibling on a node row
    Transcript, // bump a transcript row's digest (its gated init constraint)
}

fn gen_trace(paths: &[DecommitPath], n_abs: usize, height: u32, tamper: Tamper) -> Trace {
    let n_transcript = 8;
    let steps = schedule(paths.len(), n_transcript, height, n_abs);
    let n_used = steps.len();
    let log_size = (n_used as u32).next_power_of_two().trailing_zeros().max(1);
    let n = 1usize << log_size;
    let mut steps = steps;
    steps.resize(n, Step::Pad);
    let mut fills = resolve(&steps, paths, n_abs);

    // Locate tamper targets (first matching real row).
    let absorb_row = fills.iter().position(|f| f.m_abs).unwrap();
    let node_row = fills.iter().position(|f| f.m_node).unwrap();
    let tr_row = fills.iter().position(|f| f.is_tr && !f.zero_st).unwrap();
    match tamper {
        Tamper::None => {}
        Tamper::Leaf => fills[absorb_row].leaf[0] += BaseField::one(),
        Tamper::Sibling => fills[node_row].sib[0] += BaseField::one(),
        Tamper::Transcript => fills[tr_row].st_cur[0] += BaseField::one(),
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let wrap = |logical: Vec<BaseField>| {
        let mut c = Col::<CpuBackend, BaseField>::zeros(n);
        for (i, v) in logical.into_iter().enumerate() {
            c.set(storage_index(i, log_size), v);
        }
        CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, c)
    };

    // Preprocessed columns, in registration order.
    let bcol = |sel: &dyn Fn(&RowFill) -> bool| -> Vec<BaseField> {
        fills
            .iter()
            .map(|f| {
                if sel(f) {
                    BaseField::one()
                } else {
                    BaseField::zero()
                }
            })
            .collect()
    };
    let pre_b: Vec<Vec<BaseField>> = vec![
        bcol(&|f| f.is_tr),
        bcol(&|f| f.m_abs),
        bcol(&|f| f.m_final),
        bcol(&|f| f.m_node),
        bcol(&|f| f.m_root),
        bcol(&|f| f.zero_st),
        bcol(&|f| f.hash_link),
        bcol(&|f| f.cap_fwd),
    ];
    let preprocessed: Vec<_> = pre_b.into_iter().map(wrap).collect();

    // Main columns: perm (record_permutation(init)) then st[16], sib[8], bit, mux[8], leaf[8].
    let mut main_cols: Vec<Vec<BaseField>> =
        (0..N_MAIN_COLS).map(|_| Vec::with_capacity(n)).collect();
    for f in &fills {
        let mut row: Vec<BaseField> = record_permutation(f.init);
        row.extend_from_slice(&f.st_cur);
        row.extend_from_slice(&f.sib);
        row.push(BaseField::from(f.bit));
        let mux: [BaseField; 8] =
            std::array::from_fn(|j| BaseField::from(f.bit) * (f.sib[j] - f.st_cur[j]));
        row.extend_from_slice(&mux);
        row.extend_from_slice(&f.leaf);
        debug_assert_eq!(row.len(), N_MAIN_COLS);
        for (c, v) in row.into_iter().enumerate() {
            main_cols[c].push(v);
        }
    }
    let main: Vec<_> = main_cols.into_iter().map(wrap).collect();
    let _ = &mut fills;

    Trace {
        preprocessed,
        main,
        log_size,
    }
}

fn prove_and_verify(trace: Trace, root: Hash8) -> Result<(), String> {
    let config = mobile_config();
    let log_size = trace.log_size;
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
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
    let component = FrameworkComponent::<SharedPermEval>::new(
        &mut alloc,
        SharedPermEval {
            log_n_rows: log_size,
            root,
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

fn setup() -> (Vec<DecommitPath>, Hash8, usize) {
    let config = mobile_config();
    let inner = prove_inner(config);
    let qp = real_query_positions(&inner, config);
    let (paths, root) = tree_paths(&inner, 1, INNER_MAIN_COLS, HEIGHT, &qp);
    let n_abs = INNER_MAIN_COLS / 8;
    // A handful of real paths is enough to exercise the streamed mechanism.
    let paths: Vec<DecommitPath> = paths.into_iter().take(6).collect();
    (paths, root, n_abs)
}

/// FAST: the merged transcript + streamed-decommit trace satisfies the AIR.
#[test]
fn shared_perm_air_satisfied() {
    let (paths, root, n_abs) = setup();
    let trace = gen_trace(&paths, n_abs, HEIGHT, Tamper::None);
    let log_size = trace.log_size;
    let pre: Vec<Vec<M31>> = trace
        .preprocessed
        .iter()
        .map(|e| e.values.to_cpu())
        .collect();
    let main: Vec<Vec<M31>> = trace.main.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> =
        TreeVec::new(vec![pre.iter().collect(), main.iter().collect(), vec![]]);
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            SharedPermEval {
                log_n_rows: log_size,
                root,
            }
            .evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!(
        "shared_perm_air_satisfied: {} real main-tree decommit paths re-hashed in STREAMED form \
         (one perm/row), sharing the perm slot with an 8-row transcript region, at log {log_size}; \
         {} main M31 cols. Trace satisfies the AIR.",
        paths.len(),
        N_MAIN_COLS,
    );
}

/// THE GATE: the streamed decommit + transcript prove+verify through the lifted
/// Poseidon2-M31 protocol; a tampered leaf, sibling, and transcript value reject.
#[test]
fn shared_perm_gate() {
    let (paths, root, n_abs) = setup();

    prove_and_verify(gen_trace(&paths, n_abs, HEIGHT, Tamper::None), root)
        .expect("honest streamed shared-perm decommit must prove+verify");

    assert!(
        prove_and_verify(gen_trace(&paths, n_abs, HEIGHT, Tamper::Leaf), root).is_err(),
        "a tampered leaf value must be rejected"
    );
    assert!(
        prove_and_verify(gen_trace(&paths, n_abs, HEIGHT, Tamper::Sibling), root).is_err(),
        "a tampered sibling must be rejected"
    );
    assert!(
        prove_and_verify(gen_trace(&paths, n_abs, HEIGHT, Tamper::Transcript), root).is_err(),
        "a tampered transcript digest must be rejected"
    );

    eprintln!(
        "shared_perm_gate GREEN: a real proof's main trace-tree decommit re-hashes to its real \
         root in a STREAMED (one-perm/row) form — leaf sponge + every hash_children level each \
         their own row, the 16-wide state threaded row→row by a [0,1] latch, the bit-ordered \
         child select lowered to degree 2 via a witnessed mux — sharing the eval_permutation slot \
         with a transcript region under a preprocessed row-type selector; proves+verifies through \
         the lifted Poseidon2-M31 protocol; tampered leaf / sibling / transcript each rejected."
    );
}
