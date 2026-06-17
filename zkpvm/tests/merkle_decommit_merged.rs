//! Recursion build P3 — the **MerkleDecommit chip as ONE uniform component**,
//! and the resolution of the combined-prove blocker.
//!
//! ## What this gives
//!
//! A full Merkle path is re-hashed leaf→root in ONE `FrameworkEval`: each row
//! runs the `DEPTH` Poseidon2 permutations inline AND re-hashes the path against
//! them, so the compression binding is *intra-row* (the perm's witnessed output
//! `out[0..8]` IS the parent, chained directly into the next level's ordering
//! select). No second component, no cross-chip relation needed for the binding.
//! Soundness (re-derived): each level's `bit` is boolean; each level's
//! `(left,right)` are constrained to the bit-driven ordering `sel(bit,cur,sib)`
//! (degree 2); every `parent = first8(permute(left‖right))` is enforced by the
//! inline permutation; the top `cur_DEPTH` equals the public root. A row verifies
//! iff a genuine leaf→root path exists at the boolean index. All constraints are
//! degree ≤ 2.
//!
//! ## Why this shape: the custom-stack constraint
//!
//! The custom **Poseidon2-M31** lifted stack rejects (prover OODS sanity,
//! `ConstraintsNotSatisfied`) a SINGLE component that mixes the perm with
//! constraints referencing the perm's I/O masks (the decommit ordering/root)
//! **when the proof has no interaction tree** — but accepts it once the component
//! carries an interaction (logup) tree, even a redundant produce-only one. The
//! supporting facts (probes in this file + the foundation tests):
//!
//! - multi-component × multi-fraction logup proves fine on the custom stack
//!   (synthetic squares, asymmetric widths, scattered tuples);
//! - the IDENTICAL merged AIR proves through the **Blake2s** lifted stack ⇒ the
//!   AIR has no degree/soundness defect (`merged_blake2s_probe`);
//! - perm-only, and perm + up to 920 free boolean constraints, prove on the
//!   custom stack with no interaction tree ⇒ not width, not constraint count, not
//!   the round constants;
//! - the merged AIR (perm + I/O-linking constraints) with no interaction tree is
//!   rejected (`merged_no_interaction_rejected_by_custom_stack`).
//!
//! The exact stwo-internal mechanism is open; the interaction tree is the
//! empirical enabler, and soundness rests on the inline binding (the negative
//! gate rejects a tampered path). The producer/consumer split has a separate
//! residual custom-stack failure, so the **one-uniform-component + an interaction
//! tree** is the chosen shape — which is the P4 join-AIR shape anyway.
//!
//! `merged_decommit_logup_gate` (default) is the un-block: it proves+verifies and
//! rejects a tampered path. The `#[ignore]`'d probes preserve the load-bearing
//! evidence (no-interaction is rejected; Blake2s accepts the same AIR).
//!
//! Run: `cargo test -p zkpvm --test merkle_decommit_merged -- --nocapture`

mod recursion_common;

use num_traits::{One, Zero};
use recursion_common::*;
use stwo::core::air::Component;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedM31};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator,
};

const DEPTH: usize = 3; // tree height — 2^DEPTH leaves
const N_PATHS: usize = 32; // query paths verified (one per row)

type Hash8 = [BaseField; 8];
/// One permutation instance's `(input[16], output[16])` masks.
type PermIo<F> = ([F; N_STATE], [F; N_STATE]);

/// Per-row column order (must match [`record_row`]):
/// `[ leaf[8], (bit, sib[8], perm[N_PERM_COLS]) × DEPTH ]`.
const ROW_COLS: usize = 8 + DEPTH * (1 + 8 + N_PERM_COLS);

// ── The merged single-component decommit AIR (inline perm binding) ─────────

#[derive(Clone)]
struct MergedDecommitEval {
    log_n_rows: u32,
    root: Hash8,
}

impl MergedDecommitEval {
    /// The decommit constraints, shared by the plain and logup-bearing evals.
    /// Returns each level's `(init[16], out[16])` perm masks so a caller can also
    /// emit them to a relation (the interaction-tree enabler).
    fn constrain<E: EvalAtRow>(&self, eval: &mut E) -> Vec<PermIo<E::F>> {
        let one = E::F::one();
        let leaf: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
        let mut cur = leaf;
        let mut perms = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            let bit = eval.next_trace_mask();
            let sib: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone())); // boolean

            // The permutation's input[16] = left ‖ right; output[0..8] = parent.
            let (init, out) = eval_permutation(eval);

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
            perms.push((init, out));
        }
        // The recomputed root must equal the public root (all rows real).
        for j in 0..8 {
            eval.add_constraint(cur[j].clone() - E::F::from(self.root[j]));
        }
        perms
    }
}

impl FrameworkEval for MergedDecommitEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1 // degree ≤ 2 (witnessed S-box + witnessed selects)
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        self.constrain(&mut eval);
        eval
    }
}

/// The same decommit AIR, plus a produce-only logup over each level's
/// compression — present solely to give the proof an interaction tree (the
/// custom-stack enabler). The binding is the inline `constrain`; the logup is
/// redundant for soundness.
#[derive(Clone)]
struct MergedDecommitLogupEval {
    log_n_rows: u32,
    root: Hash8,
    rel: Poseidon2CompressionRelation,
}

impl FrameworkEval for MergedDecommitLogupEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let base = MergedDecommitEval {
            log_n_rows: self.log_n_rows,
            root: self.root,
        };
        let perms = base.constrain(&mut eval);
        for (init, out) in &perms {
            let mut tuple: Vec<E::F> = Vec::with_capacity(COMPRESSION_TUPLE_LEN);
            tuple.extend_from_slice(init);
            for v in out.iter().take(RATE) {
                tuple.push(v.clone());
            }
            eval.add_to_relation(RelationEntry::new(&self.rel, E::EF::one(), &tuple));
        }
        eval.finalize_logup();
        eval
    }
}

/// Trace-column indices of level `k`'s `(init[16] ‖ out[0..8])` tuple in the
/// merged layout `[leaf[8], (bit, sib[8], perm[N_PERM_COLS]) × DEPTH]`.
fn merged_perm_tuple_cols(k: usize) -> [usize; COMPRESSION_TUPLE_LEN] {
    let perm_base = 8 + k * (1 + 8 + N_PERM_COLS) + 9;
    let last_round_start = N_PERM_COLS - N_STATE * 3;
    let mut cols = [0usize; COMPRESSION_TUPLE_LEN];
    for i in 0..N_STATE {
        cols[i] = perm_base + i;
    }
    for j in 0..RATE {
        cols[N_STATE + j] = perm_base + last_round_start + 3 * j + 2;
    }
    cols
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

// ── The un-block gate: merged decommit + interaction tree ──────────────────

fn prove_merged_logup(config: PcsConfig, leaf_tamper: Option<usize>) -> Result<(), String> {
    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (paths, root) = standard_paths();

    // Build the merged trace as SIMD columns (LogupTraceGenerator is SimdBackend).
    let n = 1usize << log_size;
    let mut raw = vec![vec![BaseField::zero(); n]; ROW_COLS];
    for (row, p) in paths.iter().enumerate() {
        let s = storage_index(row, log_size);
        for (c, v) in row_values(p).into_iter().enumerate() {
            raw[c][s] = v;
        }
    }
    // Corrupt a path's committed leaf: its level-0 ordering select no longer
    // matches the (independently filled) perm input, so the inline binding breaks.
    if let Some(row) = leaf_tamper {
        raw[0][storage_index(row, log_size)] += BaseField::one();
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    let simd: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> = raw
        .into_iter()
        .map(|v| CircleEvaluation::new(domain, BaseColumn::from_iter(v)))
        .collect();

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
    tb.extend_evals(to_cpu(&simd));
    tb.commit(channel);

    let rel = Poseidon2CompressionRelation::draw(channel);

    // Interaction: DEPTH produce-only fractions, one per level's compression.
    let mut logup = LogupTraceGenerator::new(log_size);
    for k in 0..DEPTH {
        let cols = merged_perm_tuple_cols(k);
        let mut col = logup.new_col();
        for vec_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let packed: [PackedM31; COMPRESSION_TUPLE_LEN] =
                std::array::from_fn(|i| simd[cols[i]].data[vec_row]);
            col.write_frac(
                vec_row,
                PackedQM31::broadcast(SecureField::one()),
                rel.combine(&packed),
            );
        }
        col.finalize_col();
    }
    let (int_simd, claimed_sum) = logup.finalize_last();
    channel.mix_felts(&[claimed_sum]);
    let mut tb = cs.tree_builder();
    tb.extend_evals(to_cpu(&int_simd));
    tb.commit(channel);

    let component = FrameworkComponent::<MergedDecommitLogupEval>::new(
        &mut TraceLocationAllocator::default(),
        MergedDecommitLogupEval {
            log_n_rows: log_size,
            root,
            rel: rel.clone(),
        },
        claimed_sum,
    );
    let proof = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs)
        .map_err(|e| format!("prove: {e:?}"))?;

    let vch = &mut Poseidon2M31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    let _ = Poseidon2CompressionRelation::draw(vch);
    vch.mix_felts(&[claimed_sum]);
    vs.commit(proof.commitments[2], &sizes[2], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof)
        .map_err(|e| format!("verify: {e:?}"))
}

/// THE UN-BLOCK GATE: the merged decommit proves AND verifies through the lifted
/// Poseidon2-M31 protocol as ONE uniform component carrying an interaction tree;
/// a tampered path is rejected (the inline binding enforces soundness).
#[test]
fn merged_decommit_logup_gate() {
    let config = mobile_config();
    prove_merged_logup(config, None).expect("honest merged+logup decommit must verify");
    assert!(
        prove_merged_logup(config, Some(0)).is_err(),
        "a tampered path must be rejected (prove or verify fails)"
    );
    eprintln!(
        "merged_decommit_logup_gate GREEN: {N_PATHS} Merkle paths (depth {DEPTH}) re-hashed \
         leaf→root in ONE uniform component through the lifted Poseidon2-M31 protocol (no \
         Blake2s); a tampered path is rejected."
    );
}

/// FAST: the honest merged trace satisfies the AIR on the trace domain (drives
/// `AssertEvaluator` row-by-row). Validates the inline binding independent of the
/// (separately gated) full prove.
#[test]
fn merged_decommit_air_satisfied() {
    use stwo::core::fields::m31::M31;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (paths, root) = standard_paths();
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
    let main: Vec<Vec<M31>> = cols.iter().map(|c| c.to_cpu()).collect();
    let trace: TreeVec<Vec<&Vec<M31>>> = TreeVec::new(vec![vec![], main.iter().collect(), vec![]]);
    let eval = MergedDecommitEval {
        log_n_rows: log_size,
        root,
    };
    assert_constraints_on_trace(
        &trace,
        log_size,
        |e| {
            eval.evaluate(e);
        },
        SecureField::zero(),
    );
    eprintln!("merged_decommit_air_satisfied: trace satisfies the AIR on the trace domain");
}

// ── Evidence probes for the blocker characterization (slow; `--ignored`) ───

/// Builds the merged trace as CpuBackend columns (no interaction tree).
fn merged_cpu_trace(
    log_size: u32,
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
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

/// EVIDENCE: WITHOUT an interaction tree, the custom Poseidon2-M31 stack rejects
/// the merged AIR (the trigger). Asserts the prove FAILS — documenting the
/// custom-stack quirk that `merged_decommit_logup_gate` works around.
#[test]
#[ignore = "slow (~90s); documents the no-interaction-tree trigger"]
fn merged_no_interaction_rejected_by_custom_stack() {
    let config = mobile_config();
    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (_, root) = standard_paths();
    let trace = merged_cpu_trace(log_size);

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
    let res = prove::<CpuBackend, P2MerkleChannel>(&[&component], channel, cs);
    assert!(
        res.is_err(),
        "EXPECTED: custom stack rejects the merged AIR with no interaction tree"
    );
    eprintln!("merged_no_interaction_rejected_by_custom_stack: confirmed ConstraintsNotSatisfied");
}

/// EVIDENCE: the IDENTICAL merged AIR proves+verifies through the **Blake2s**
/// lifted stack — so the rejection above is custom-stack-specific, NOT a degree
/// or soundness defect in the AIR.
#[test]
#[ignore = "slow (~20s); documents that Blake2s accepts the same AIR"]
fn merged_blake2s_probe() {
    use stwo::core::channel::Blake2sM31Channel;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;

    let config = mobile_config();
    let log_size = (N_PATHS as u32).next_power_of_two().trailing_zeros();
    let (_, root) = standard_paths();
    let trace = merged_cpu_trace(log_size);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let channel = &mut Blake2sM31Channel::default();
    let mut cs =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
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
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(&[&component], channel, cs)
        .expect("BLAKE2S prove of merged decommit");
    let vch = &mut Blake2sM31Channel::default();
    let mut vs = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    vs.commit(proof.commitments[0], &sizes[0], vch);
    vs.commit(proof.commitments[1], &sizes[1], vch);
    verify(&[&component as &dyn Component], vch, &mut vs, proof).expect("BLAKE2S verify");
    eprintln!("merged_blake2s_probe: PROVE+VERIFY OK through the Blake2s lifted stack");
}
