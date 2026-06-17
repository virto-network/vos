//! Recursion build P3 — the **MerkleDecommit chip as ONE uniform component**.
//!
//! A full Merkle path is re-hashed leaf→root in ONE `FrameworkEval`: each row
//! runs the `DEPTH` Poseidon2 permutations inline AND re-hashes the path against
//! them, so the compression binding is *intra-row* — the perm's witnessed output
//! `out[0..8]` IS the parent, chained directly into the next level's ordering
//! select. No second component, no cross-chip relation, no interaction tree.
//! Soundness (re-derived): each level's `bit` is boolean; each level's
//! `(left,right)` are constrained to the bit-driven ordering `sel(bit,cur,sib)`
//! (degree 2); every `parent = first8(permute(left‖right))` is enforced by the
//! inline permutation; the top `cur_DEPTH` equals the public root. A row verifies
//! iff a genuine leaf→root path exists at the boolean index. All constraints are
//! degree ≤ 2. This is the P4 join-AIR's uniform shape.
//!
//! ## What proves and what does not (custom Poseidon2-M31 lifted stack)
//!
//! - **This single-component decommit proves+verifies** through the custom stack
//!   (`merged_decommit_gate`), and a tampered path is rejected.
//! - The producer/consumer SPLIT (`merkle_decommit.rs::poseidon2_merkle_decommit`)
//!   still trips the prover's OODS sanity (`ConstraintsNotSatisfied`) on a clean
//!   build — a genuine residual custom-stack issue with multiple components.
//!   Hence the one-uniform-component shape here.
//!
//! ## ⚠ Build gotcha that cost a full investigation
//!
//! For most of one session this single-component AIR *appeared* to fail the OODS
//! sanity unless it carried a redundant interaction tree. That was a **stale /
//! incrementally-miscompiled cached stwo rlib**: deterministic (so it looked like
//! a real property), fixed by a clean rebuild (`cargo clean -p stwo` — or pointing
//! at a freshly-built stwo). Three independent fresh builds (the olanod/stwo fork
//! worktree, and a clean starkware-git rebuild) all prove it fine with no tree.
//! Lesson: on an inexplicable `ConstraintsNotSatisfied` from the prover, rebuild
//! stwo cleanly before theorizing. (The multi-component failure above survives a
//! clean rebuild — that one is real.)
//!
//! Run: `cargo test -p zkpvm --test merkle_decommit_merged -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::*;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

const DEPTH: usize = 3; // tree height — 2^DEPTH leaves
const N_PATHS: usize = 32; // query paths verified (one per row)

type Hash8 = [BaseField; 8];

/// Per-row column order (must match [`row_values`]):
/// `[ leaf[8], (bit, sib[8], perm[N_PERM_COLS]) × DEPTH ]`.
const ROW_COLS: usize = 8 + DEPTH * (1 + 8 + N_PERM_COLS);

// ── The merged single-component decommit AIR (inline perm binding) ─────────

#[derive(Clone)]
struct MergedDecommitEval {
    log_n_rows: u32,
    root: Hash8,
}

impl FrameworkEval for MergedDecommitEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2 (witnessed S-box + witnessed selects)
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one = E::F::one();
        let leaf: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let mut cur = leaf;
        for _ in 0..DEPTH {
            let bit = eval.next_trace_mask();
            let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone())); // boolean

            // The permutation's input[16] = left ‖ right; output[0..8] = parent.
            let (init, out) = eval_permutation(&mut eval);

            // bit==0 ⇒ cur is the LEFT child; bit==1 ⇒ cur is the RIGHT child.
            for j in 0..8 {
                let sel_left =
                    (one.clone() - bit.clone()) * cur[j].clone() + bit.clone() * sib[j].clone();
                let sel_right =
                    (one.clone() - bit.clone()) * sib[j].clone() + bit.clone() * cur[j].clone();
                eval.add_constraint(init[j].clone() - sel_left); // left  == perm input[0..8]
                eval.add_constraint(init[8 + j].clone() - sel_right); // right == perm input[8..16]
            }
            cur = std::array::from_fn(|j| out[j].clone()); // parent → next level's cur
        }
        // The recomputed root must equal the public root (all rows real).
        for j in 0..8 {
            eval.add_constraint(cur[j].clone() - E::F::from(self.root[j]));
        }
        eval
    }
}

// ── Host Merkle tree + path extraction ────────────────────────────────────

fn build_tree(leaves: Vec<Hash8>) -> Vec<Vec<Hash8>> {
    let mut tree = vec![leaves];
    while tree.last().unwrap().len() > 1 {
        let lvl = tree.last().unwrap();
        let next: Vec<Hash8> = lvl
            .chunks(2)
            .map(|c| hash_children_m31(&c[0], &c[1]))
            .collect();
        tree.push(next);
    }
    tree
}

struct Path {
    leaf: Hash8,
    bits: [u32; DEPTH],
    sibs: [Hash8; DEPTH],
    lr: [(Hash8, Hash8); DEPTH],
}

fn extract_path(tree: &[Vec<Hash8>], idx: usize) -> Path {
    let mut ci = idx;
    let leaf = tree[0][idx];
    let mut bits = [0u32; DEPTH];
    let mut sibs = [[BaseField::zero(); 8]; DEPTH];
    let mut lr = [([BaseField::zero(); 8], [BaseField::zero(); 8]); DEPTH];
    for k in 0..DEPTH {
        let node = tree[k][ci];
        let bit = (ci & 1) as u32;
        let sib = tree[k][ci ^ 1];
        bits[k] = bit;
        sibs[k] = sib;
        lr[k] = if bit == 0 { (node, sib) } else { (sib, node) };
        ci >>= 1;
    }
    Path {
        leaf,
        bits,
        sibs,
        lr,
    }
}

fn storage_index(i: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size)
}

fn standard_paths() -> (Vec<Path>, Hash8) {
    let leaves: Vec<Hash8> = (0..(1usize << DEPTH))
        .map(|i| std::array::from_fn(|j| BaseField::from_u32_unchecked((i * 8 + j + 1) as u32)))
        .collect();
    let tree = build_tree(leaves);
    let root = tree[DEPTH][0];
    let paths = (0..N_PATHS)
        .map(|i| extract_path(&tree, i % (1 << DEPTH)))
        .collect();
    (paths, root)
}

/// One path's row values, in the exact column order the eval reads its masks.
fn row_values(p: &Path) -> Vec<BaseField> {
    let mut row = Vec::with_capacity(ROW_COLS);
    row.extend_from_slice(&p.leaf);
    for k in 0..DEPTH {
        row.push(BaseField::from(p.bits[k]));
        row.extend_from_slice(&p.sibs[k]);
        let mut init = [BaseField::zero(); N_STATE];
        init[..8].copy_from_slice(&p.lr[k].0);
        init[8..].copy_from_slice(&p.lr[k].1);
        row.extend(record_permutation(init));
    }
    debug_assert_eq!(row.len(), ROW_COLS);
    row
}

fn gen_trace(
    log_size: u32,
    leaf_tamper: Option<usize>,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let (paths, _) = standard_paths();
    let n = 1usize << log_size;
    let mut cols: Vec<Col<CpuBackend, BaseField>> = (0..ROW_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n))
        .collect();
    for (row, p) in paths.iter().enumerate() {
        let s = storage_index(row, log_size);
        for (c, v) in row_values(p).into_iter().enumerate() {
            cols[c].set(s, v);
        }
    }
    // Corrupt a path's committed leaf: its level-0 ordering select no longer
    // matches the (independently filled) perm input, so the path no longer
    // re-hashes to the committed root.
    if let Some(row) = leaf_tamper {
        let s = storage_index(row, log_size);
        let orig = cols[0].at(s);
        cols[0].set(s, orig + BaseField::one());
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

// ── Prove + verify (ONE component, no interaction tree) ────────────────────

fn prove_and_verify(config: PcsConfig, leaf_tamper: Option<usize>) -> Result<(), String> {
    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (_, root) = standard_paths();
    let trace = gen_trace(log_size, leaf_tamper);

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

    let component = FrameworkComponent::<MergedDecommitEval>::new(
        &mut TraceLocationAllocator::default(),
        MergedDecommitEval {
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

/// THE GATE: the merged decommit (perm inline, no interaction tree) proves AND
/// verifies through the lifted Poseidon2-M31 protocol as ONE uniform component;
/// a tampered path is rejected.
#[test]
fn merged_decommit_gate() {
    let config = mobile_config();
    prove_and_verify(config, None).expect("honest merged decommit must verify");
    assert!(
        prove_and_verify(config, Some(0)).is_err(),
        "a tampered path must be rejected (prove or verify fails)"
    );
    eprintln!(
        "merged_decommit_gate GREEN: {N_PATHS} Merkle paths (depth {DEPTH}) re-hashed \
         leaf→root in ONE uniform component (perm inline, no interaction tree) through the \
         lifted Poseidon2-M31 protocol (no Blake2s); a tampered path is rejected."
    );
}

/// FAST: the honest merged trace satisfies the AIR on the trace domain (drives
/// `AssertEvaluator` row-by-row). Validates the inline binding independent of the
/// full prove.
#[test]
fn merged_decommit_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (_, root) = standard_paths();
    let trace = gen_trace(log_size, None);
    let main: Vec<Vec<M31>> = trace.iter().map(|e| e.values.to_cpu()).collect();
    let tv: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = MergedDecommitEval {
        log_n_rows: log_size,
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
    eprintln!("merged_decommit_air_satisfied: trace satisfies the AIR on the trace domain");
}
