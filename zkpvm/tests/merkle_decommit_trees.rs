//! Recursion build P4.1 — **GATE 3: multi-tree Merkle decommit vs a real proof.**
//!
//! `merkle_decommit_merged.rs` re-hashes ONE precomputed path leaf→root. This
//! gate verifies a REAL small Poseidon2-M31 proof's trace-tree decommitments —
//! the dominant verifier cost — reproducing `MerkleVerifierLifted::verify`
//! (`vcs_lifted/verifier.rs:103-193`) in-AIR against the proof's REAL
//! `queried_values`, `decommitments.hash_witness`, and commitment roots:
//!
//!   * the **leaf** is the real sponge `update_leaf(row) + finalize`
//!     (`recursion_common::P2MerkleHasher`) over the row of queried column values
//!     at a position — `n_leaf_cols/8` rate absorbs + a padded finalize perm
//!     (3 perms for the 16-column main tree, 2 for the 8-column composition tree);
//!   * each of the `height` internal layers is a `hash_children`
//!     (`first8(permute(left‖right))`) with the bit-driven child ordering
//!     (`vcs_lifted/verifier.rs:168-178`);
//!   * the recomputed root is pinned to the proof's commitment.
//!
//! The proof's compressed `hash_witness` + the co-queried sub-paths are expanded
//! host-side by replaying `verify`'s exact bottom-up fold (sibling `chunk_by`,
//! `idx&1` ordering, witness-fetch-on-singletons) into a full node map; the
//! per-query sibling at each level is then a real node (a witness hash or a
//! co-queried subtree root). Binding the leaf values to the real `queried_values`
//! and pinning the real root makes the in-AIR re-hash equivalent to consuming the
//! decommitment (collision-resistance + a fixed public root bind every sibling).
//!
//! Two trees of different leaf widths (main = 16 cols, composition = 8 cols, both
//! height 7) are verified by the SAME generic gadget — the multi-tree shape. The
//! FRI-layer trees are the identical `MerkleVerifierLifted::verify` on
//! SECURE_EXTENSION_DEGREE-wide QM31 leaves whose values come from the FRI fold
//! reconstruction; they fold into the assembled verifier (GATE 4).
//!
//! ONE uniform `FrameworkEval` per tree (perm inline, no interaction tree — the
//! `merkle_decommit_merged.rs` proven shape), all constraints degree ≤ 2.
//!
//! GREEN GATE: a real proof's main + composition decommitment paths re-hash to
//! their real roots in-AIR and prove+verify through the lifted Poseidon2-M31
//! protocol; a tampered queried value OR a tampered sibling is rejected.
//!
//! Run: `cargo test -p zkpvm --test merkle_decommit_trees -- --nocapture`

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
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{COMPOSITION_LOG_SPLIT, verify};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

// ── A representative inner proof (a·b == out, a·a⁻¹ == 1, 16 main columns) ──────

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

/// Replay the verifier transcript through `sample_query_positions` to recover the
/// REAL drawn query positions (the indices the trace trees decommit at).
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

/// The leaf hash of a queried row: the real sponge `update_leaf(row) + finalize`.
fn sponge_leaf(row: &[BaseField]) -> Hash8 {
    let mut h = P2MerkleHasher::default();
    h.update_leaf(row);
    h.finalize().0
}

/// One query position's leaf→root path through the node map.
struct DecommitPath {
    leaf_vals: Vec<BaseField>, // the queried row (n_leaf_cols values)
    bits: Vec<u32>,            // per level: (node_index >> level) & 1
    sibs: Vec<Hash8>,          // per level: the sibling node hash
}

/// Replays `MerkleVerifierLifted::verify`'s bottom-up fold for a uniform-height
/// tree, capturing EVERY node hash (computed parents + witness-fetched siblings)
/// per level — so each query's path siblings are real nodes. Asserts the
/// recomputed root equals `root` (i.e. the real decommitment verifies).
fn decommit_node_map(
    height: u32,
    root: Hash8,
    query_positions: &[usize],
    queried_values: &[Vec<BaseField>], // [n_cols][n_queries]
    hash_witness: &[P2Hash],
) -> Vec<HashMap<usize, Hash8>> {
    let n_cols = queried_values.len();
    let mut node_map: Vec<HashMap<usize, Hash8>> = vec![HashMap::new(); (height + 1) as usize];

    // Build the leaves (distinct, ascending query positions).
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

/// All decommit paths for a tree: real query positions, real queried rows, real
/// siblings (verified against the real root).
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

// ── The generic multi-tree decommit AIR (sponge leaf + inline hash_children) ───

#[derive(Clone)]
struct DecommitEval {
    log_n_rows: u32,
    n_leaf_cols: usize,
    height: u32,
    root: Hash8,
}

/// Per-row column count for a tree of `n_leaf_cols` columns and `height`:
/// `leaf_vals + (n_leaf_cols/8 + 1) leaf perms + height·(bit + sib[8] + perm)`.
fn row_cols(n_leaf_cols: usize, height: u32) -> usize {
    let n_leaf_perms = n_leaf_cols / 8 + 1;
    n_leaf_cols + n_leaf_perms * N_PERM_COLS + height as usize * (1 + 8 + N_PERM_COLS)
}

impl FrameworkEval for DecommitEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        assert_eq!(
            self.n_leaf_cols % 8,
            0,
            "leaf width must be a multiple of RATE"
        );
        let one = E::F::one();

        // ── Leaf sponge: update_leaf(row) + finalize. ──
        let leaf_vals: Vec<E::F> = (0..self.n_leaf_cols)
            .map(|_| eval.next_trace_mask())
            .collect();
        let n_absorb = self.n_leaf_cols / 8;
        let mut prev: Option<[E::F; N_STATE]> = None;
        for chunk in 0..n_absorb {
            let (init, out) = eval_permutation(&mut eval);
            for i in 0..8 {
                let base = prev.as_ref().map_or(E::F::zero(), |p| p[i].clone());
                eval.add_constraint(init[i].clone() - (base + leaf_vals[chunk * 8 + i].clone()));
                let cap = prev.as_ref().map_or(E::F::zero(), |p| p[8 + i].clone());
                eval.add_constraint(init[8 + i].clone() - cap);
            }
            prev = Some(out);
        }
        // finalize: absorb [1, 0, …, 0] into the rate, permute.
        let (init, out) = eval_permutation(&mut eval);
        let prev = prev.expect("at least one absorb");
        for i in 0..8 {
            let add = if i == 0 { one.clone() } else { E::F::zero() };
            eval.add_constraint(init[i].clone() - (prev[i].clone() + add));
            eval.add_constraint(init[8 + i].clone() - prev[8 + i].clone());
        }
        let mut cur: [E::F; 8] = std::array::from_fn(|j| out[j].clone());

        // ── height internal layers: hash_children with bit-driven ordering. ──
        for _ in 0..self.height {
            let bit = eval.next_trace_mask();
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
            let (init, out) = eval_permutation(&mut eval);
            for j in 0..8 {
                let sel_left =
                    (one.clone() - bit.clone()) * cur[j].clone() + bit.clone() * sib[j].clone();
                let sel_right =
                    (one.clone() - bit.clone()) * sib[j].clone() + bit.clone() * cur[j].clone();
                eval.add_constraint(init[j].clone() - sel_left);
                eval.add_constraint(init[8 + j].clone() - sel_right);
            }
            cur = std::array::from_fn(|j| out[j].clone());
        }

        // ── pin the recomputed root. ──
        for j in 0..8 {
            eval.add_constraint(cur[j].clone() - E::F::from(self.root[j]));
        }
        eval
    }
}

// ── Host trace fill (same order the eval reads) ───────────────────────────────

fn row_values(p: &DecommitPath) -> Vec<BaseField> {
    let mut row = Vec::new();
    row.extend_from_slice(&p.leaf_vals);

    // Leaf sponge: absorb full rate chunks, then a padded finalize.
    let mut state = [BaseField::zero(); N_STATE];
    let n_absorb = p.leaf_vals.len() / 8;
    for chunk in 0..n_absorb {
        for i in 0..8 {
            state[i] += p.leaf_vals[chunk * 8 + i];
        }
        row.extend(record_permutation(state));
        permute(&mut state);
    }
    state[0] += BaseField::one();
    row.extend(record_permutation(state));
    permute(&mut state);
    let mut cur: Hash8 = std::array::from_fn(|j| state[j]);

    // Internal layers.
    for level in 0..p.bits.len() {
        let bit = p.bits[level];
        let sib = p.sibs[level];
        row.push(BaseField::from(bit));
        row.extend_from_slice(&sib);
        let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
        let mut init = [BaseField::zero(); N_STATE];
        init[..8].copy_from_slice(&left);
        init[8..].copy_from_slice(&right);
        row.extend(record_permutation(init));
        permute(&mut init);
        cur = std::array::from_fn(|j| init[j]);
    }
    debug_assert_eq!(cur, p.leaf_vals_root_marker());
    row
}

impl DecommitPath {
    /// Recompute the path root host-side (for the trace fill debug check).
    fn leaf_vals_root_marker(&self) -> Hash8 {
        let mut state = [BaseField::zero(); N_STATE];
        let n_absorb = self.leaf_vals.len() / 8;
        for chunk in 0..n_absorb {
            for i in 0..8 {
                state[i] += self.leaf_vals[chunk * 8 + i];
            }
            permute(&mut state);
        }
        state[0] += BaseField::one();
        permute(&mut state);
        let mut cur: Hash8 = std::array::from_fn(|j| state[j]);
        for level in 0..self.bits.len() {
            let sib = self.sibs[level];
            let (left, right) = if self.bits[level] == 0 {
                (cur, sib)
            } else {
                (sib, cur)
            };
            cur = hash_children_m31(&left, &right);
        }
        cur
    }
}

fn gen_trace(
    paths: &[DecommitPath],
    n_leaf_cols: usize,
    height: u32,
    log_size: u32,
    tamper: Option<(usize, usize)>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n = 1usize << log_size;
    let cols_n = row_cols(n_leaf_cols, height);
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..cols_n)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for r in 0..n {
        let p = &paths[r % paths.len()];
        for (c, v) in row_values(p).into_iter().enumerate() {
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

fn prove_and_verify(
    paths: &[DecommitPath],
    n_leaf_cols: usize,
    height: u32,
    root: Hash8,
    log_size: u32,
    tamper: Option<(usize, usize)>,
) -> Result<(), String> {
    let config = mobile_config();
    let trace = gen_trace(paths, n_leaf_cols, height, log_size, tamper);
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

    let component = FrameworkComponent::<DecommitEval>::new(
        &mut TraceLocationAllocator::default(),
        DecommitEval {
            log_n_rows: log_size,
            n_leaf_cols,
            height,
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

const HEIGHT: u32 = 7; // lifting_log_size for the inner proof (probe-confirmed)
const N_PROVE_PATHS: usize = 8; // real paths run through the slow lifted prove (assert covers all)

fn assert_air(paths: &[DecommitPath], n_leaf_cols: usize, height: u32, root: Hash8) {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let log_size = (paths.len() as u32)
        .next_power_of_two()
        .trailing_zeros()
        .max(1);
    let trace = gen_trace(paths, n_leaf_cols, height, log_size, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = DecommitEval {
        log_n_rows: log_size,
        n_leaf_cols,
        height,
        root,
    };
    assert_constraints_on_trace(
        &tv,
        log_size,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
}

/// FAST: ALL of a real proof's main + composition decommitment paths satisfy the
/// AIR (drives AssertEvaluator; also runs `decommit_node_map`'s root cross-check).
#[test]
fn merkle_decommit_trees_air_satisfied() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let qp = real_query_positions(&inner, config);

    let (main_paths, main_root) = tree_paths(&inner, 1, INNER_MAIN_COLS, HEIGHT, &qp);
    let (comp_paths, comp_root) = tree_paths(&inner, 2, N_COMPOSITION_COLS, HEIGHT, &qp);
    assert_air(&main_paths, INNER_MAIN_COLS, HEIGHT, main_root);
    assert_air(&comp_paths, N_COMPOSITION_COLS, HEIGHT, comp_root);

    eprintln!(
        "merkle_decommit_trees_air_satisfied: {} main ({INNER_MAIN_COLS}-col) + {} composition \
         ({N_COMPOSITION_COLS}-col) real decommit paths (height {HEIGHT}, real queried_values + \
         hash_witness, root cross-checked) satisfy the AIR.",
        main_paths.len(),
        comp_paths.len()
    );
}

/// THE GATE: real main + composition decommitment paths re-hash to their real
/// roots in-AIR and prove+verify through the lifted Poseidon2-M31 protocol; a
/// tampered queried value and a tampered sibling are both rejected.
#[test]
fn merkle_decommit_trees_gate() {
    let config = mobile_config();
    let inner = prove_inner(config);
    let qp = real_query_positions(&inner, config);

    let (main_paths, main_root) = tree_paths(&inner, 1, INNER_MAIN_COLS, HEIGHT, &qp);
    let (comp_paths, comp_root) = tree_paths(&inner, 2, N_COMPOSITION_COLS, HEIGHT, &qp);

    let main: Vec<DecommitPath> = main_paths.into_iter().take(N_PROVE_PATHS).collect();
    let comp: Vec<DecommitPath> = comp_paths.into_iter().take(N_PROVE_PATHS).collect();
    let log_size = (N_PROVE_PATHS as u32).next_power_of_two().trailing_zeros();

    // main tree: honest verifies, tampered queried value + tampered sibling reject.
    prove_and_verify(&main, INNER_MAIN_COLS, HEIGHT, main_root, log_size, None)
        .expect("honest main decommit must verify");
    assert!(
        prove_and_verify(
            &main,
            INNER_MAIN_COLS,
            HEIGHT,
            main_root,
            log_size,
            Some((0, 0))
        )
        .is_err(),
        "a tampered queried value must be rejected"
    );
    // First sibling column: leaf_vals + leaf perms, then bit(1) at level 0.
    let sib0_col = INNER_MAIN_COLS + (INNER_MAIN_COLS / 8 + 1) * N_PERM_COLS + 1;
    assert!(
        prove_and_verify(
            &main,
            INNER_MAIN_COLS,
            HEIGHT,
            main_root,
            log_size,
            Some((sib0_col, 0))
        )
        .is_err(),
        "a tampered sibling hash must be rejected"
    );

    // composition tree (8-col leaf): the SAME gadget verifies.
    prove_and_verify(&comp, N_COMPOSITION_COLS, HEIGHT, comp_root, log_size, None)
        .expect("honest composition decommit must verify");

    eprintln!(
        "merkle_decommit_trees_gate GREEN: a real proof's main ({INNER_MAIN_COLS}-col) + \
         composition ({N_COMPOSITION_COLS}-col) Merkle decommitment paths (real queried_values + \
         hash_witness, sponge leaf + hash_children, root pinned) re-hash to their real roots \
         in-AIR via ONE uniform gadget and prove+verify through the lifted Poseidon2-M31 protocol \
         ({N_PROVE_PATHS} paths/tree); a tampered queried value and a tampered sibling are rejected."
    );
}
