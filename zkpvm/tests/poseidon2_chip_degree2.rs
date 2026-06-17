//! Recursion build P2: a **degree-2** Poseidon2-over-M31 permutation AIR that
//! proves+verifies through stwo's **lifted** protocol at the MOBILE blowup-4
//! config. The foundation chip the verifier-AIR will reuse ~16K times per
//! inner-proof verify (the verifier-AIR is ~99.5% Poseidon2 hashing).
//!
//! ## Why this gate
//!
//! The stwo `examples/poseidon` AIR constrains the x^5 S-box as a single
//! degree-5 constraint (`out - pow5(matrix(state+const))`), i.e.
//! `LOG_CONSTRAINT_DEGREE_BOUND=2` — which the lifted protocol does NOT accept
//! (its degree-≥2 test is `#[ignore]`'d). Every zkpvm chip runs at degree ≤ 2
//! (`LOG_CONSTRAINT_DEGREE_BOUND=1`). So the verifier-AIR's Poseidon2 chip must
//! **flatten** the S-box: witness the intermediate powers so each constraint is
//! degree ≤ 2:
//!   y2 = y·y         (deg 2, y is the degree-1 post-matrix expression)
//!   y4 = y2·y2       (deg 2)
//!   out = y4·y       (deg 2)  → out is the post-S-box state, witnessed (degree 1)
//! 3 helper columns + 3 degree-2 constraints per S-box element, replacing the
//! example's 1 column + 1 degree-5 constraint.
//!
//! GREEN here = a real flattened width-16 Poseidon2 permutation proves+verifies
//! through the lifted protocol at blowup 4 (`LOG_CONSTRAINT_DEGREE_BOUND=1`), and
//! a corrupted witness is rejected. This validates the degree-flatten idiom every
//! verifier-AIR chip depends on. Constants are the example's placeholder `1234`
//! (the degree/protocol question is independent of constant quality; vetted
//! constants are P1).
//!
//! Run: `cargo test -p zkpvm --test poseidon2_chip_degree2 -- --nocapture`

use std::ops::{Add, AddAssign, Mul, Sub};

use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

// ── Poseidon2-over-M31 parameters (width 16; eprint 2023/323 §5) ──────────

const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 14;
const N_HALF_FULL_ROUNDS: usize = 4;
const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;

// Placeholder constants (P1 swaps in vetted ones).
const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; FULL_ROUNDS];
const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

/// Trace columns per permutation instance (one per row): 16 initial-state cols
/// + 3 S-box helper cols (y2,y4,out) per state element per full round + 3 per
/// partial round (only state[0] gets the S-box).
const N_COLS: usize = N_STATE + FULL_ROUNDS * (N_STATE * 3) + N_PARTIAL_ROUNDS * 3;

fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * BaseField::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

// ── Host trace recorder: produce the per-row column values in eval order ──

/// Run the permutation on `state`, pushing the column values in EXACTLY the
/// order [`Poseidon2PermEval::evaluate`] reads them (16 initial, then per full
/// round per element y2,y4,out, then per partial round y2,y4,out). The output
/// length is [`N_COLS`].
fn record_full_round(
    state: &mut [BaseField; N_STATE],
    consts: &[BaseField; N_STATE],
    cols: &mut Vec<BaseField>,
) {
    for i in 0..N_STATE {
        state[i] += consts[i];
    }
    apply_external_round_matrix(state);
    for i in 0..N_STATE {
        let y = state[i];
        let y2 = y * y;
        let y4 = y2 * y2;
        let out = y4 * y;
        cols.push(y2);
        cols.push(y4);
        cols.push(out);
        state[i] = out;
    }
}

fn record_permutation(mut state: [BaseField; N_STATE]) -> Vec<BaseField> {
    let mut cols = Vec::with_capacity(N_COLS);
    for s in state.iter() {
        cols.push(*s);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        record_full_round(&mut state, &EXTERNAL_ROUND_CONSTS[round], &mut cols);
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += INTERNAL_ROUND_CONSTS[round];
        apply_internal_round_matrix(&mut state);
        let y = state[0];
        let y2 = y * y;
        let y4 = y2 * y2;
        let out = y4 * y;
        cols.push(y2);
        cols.push(y4);
        cols.push(out);
        state[0] = out;
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        record_full_round(
            &mut state,
            &EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS],
            &mut cols,
        );
    }
    debug_assert_eq!(cols.len(), N_COLS);
    cols
}

// ── The degree-2 Poseidon2 permutation AIR ───────────────────────────────

#[derive(Clone)]
struct Poseidon2PermEval {
    log_n_rows: u32,
}

impl Poseidon2PermEval {
    /// Constrain one full round (add const → external matrix → flattened x^5 on
    /// all 16 lanes), advancing `state` to the witnessed post-S-box masks.
    fn full_round<E: EvalAtRow>(
        eval: &mut E,
        state: &mut [E::F; N_STATE],
        consts: &[BaseField; N_STATE],
    ) {
        for i in 0..N_STATE {
            state[i] += consts[i];
        }
        apply_external_round_matrix(state);
        for i in 0..N_STATE {
            state[i] = sbox_flatten(eval, state[i].clone());
        }
    }
}

/// Flatten x^5 to three degree-2 constraints with witnessed intermediates.
fn sbox_flatten<E: EvalAtRow>(eval: &mut E, y: E::F) -> E::F {
    let y2 = eval.next_trace_mask();
    eval.add_constraint(y2.clone() - y.clone() * y.clone());
    let y4 = eval.next_trace_mask();
    eval.add_constraint(y4.clone() - y2.clone() * y2.clone());
    let out = eval.next_trace_mask();
    eval.add_constraint(out.clone() - y4 * y);
    out
}

impl FrameworkEval for Poseidon2PermEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // All constraints are degree ≤ 2 (flattened S-box): +1 is the bound,
        // same as the lifted wide_fibonacci path.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut state: [E::F; N_STATE] = std::array::from_fn(|_| eval.next_trace_mask());
        for round in 0..N_HALF_FULL_ROUNDS {
            Self::full_round(&mut eval, &mut state, &EXTERNAL_ROUND_CONSTS[round]);
        }
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] += INTERNAL_ROUND_CONSTS[round];
            apply_internal_round_matrix(&mut state);
            state[0] = sbox_flatten(&mut eval, state[0].clone());
        }
        for round in 0..N_HALF_FULL_ROUNDS {
            Self::full_round(
                &mut eval,
                &mut state,
                &EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS],
            );
        }
        eval
    }
}

/// One permutation instance per row, seeded distinctly per row — raw columns.
fn gen_cols(log_size: u32) -> Vec<Col<CpuBackend, BaseField>> {
    let n_rows = 1usize << log_size;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n_rows))
        .collect();
    for row in 0..n_rows {
        let init: [BaseField; N_STATE] =
            std::array::from_fn(|i| BaseField::from_u32_unchecked((row * N_STATE + i) as u32));
        let vals = record_permutation(init);
        for (c, v) in vals.into_iter().enumerate() {
            trace[c].set(row, v);
        }
    }
    trace
}

fn wrap_cols(
    cols: Vec<Col<CpuBackend, BaseField>>,
    log_size: u32,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect()
}

fn mobile_config() -> PcsConfig {
    // MOBILE: blowup 4 (log_blowup_factor=2), 38 queries, 20-bit PoW.
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

#[test]
fn poseidon2_degree2_lifted_blowup4() {
    const LOG_N_ROWS: u32 = 5;
    let config = mobile_config();

    let prove_once = |trace: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>| {
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let prover_channel = &mut Blake2sM31Channel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
        let mut tb = commitment_scheme.tree_builder();
        tb.extend_evals(Vec::new());
        tb.commit(prover_channel);
        let mut tb = commitment_scheme.tree_builder();
        tb.extend_evals(trace);
        tb.commit(prover_channel);
        let component = FrameworkComponent::<Poseidon2PermEval>::new(
            &mut TraceLocationAllocator::default(),
            Poseidon2PermEval {
                log_n_rows: LOG_N_ROWS,
            },
            SecureField::zero(),
        );
        let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        );
        (component, proof)
    };

    // ── Positive: honest permutation trace proves + verifies through lifted ──
    let (component, proof) = prove_once(wrap_cols(gen_cols(LOG_N_ROWS), LOG_N_ROWS));
    let proof = proof.expect("prove the degree-2 Poseidon2 permutation (lifted, blowup 4)");

    let verifier_channel = &mut Blake2sM31Channel::default();
    let mut verifier_scheme = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    verifier_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    verifier_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verify(&[&component], verifier_channel, &mut verifier_scheme, proof)
        .expect("verify the degree-2 Poseidon2 permutation proof");

    // ── Negative: a corrupted S-box witness must NOT verify (constraints bind) ──
    let mut bad_cols = gen_cols(LOG_N_ROWS);
    // Flip the first full round's element-0 `out` column (index 16 + 2) at row 0.
    let bad_col = N_STATE + 2;
    let orig = bad_cols[bad_col].at(0);
    bad_cols[bad_col].set(0, orig + BaseField::from_u32_unchecked(1));
    let (bad_component, bad_proof) = prove_once(wrap_cols(bad_cols, LOG_N_ROWS));
    // stwo's prover does not enforce constraints, so a bad trace either fails to
    // prove or produces a proof the verifier rejects — accept either.
    let rejected = match bad_proof {
        Err(_) => true,
        Ok(p) => {
            let vch = &mut Blake2sM31Channel::default();
            let mut vs = CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
            let sizes = bad_component.trace_log_degree_bounds();
            vs.commit(p.commitments[0], &sizes[0], vch);
            vs.commit(p.commitments[1], &sizes[1], vch);
            verify(&[&bad_component], vch, &mut vs, p).is_err()
        }
    };
    assert!(
        rejected,
        "a corrupted Poseidon2 S-box witness must be rejected (constraints non-vacuous)"
    );

    eprintln!(
        "poseidon2_degree2_lifted_blowup4 GREEN: a flattened degree-2 width-16 Poseidon2-M31 \
         permutation ({N_COLS} cols/instance) proves+verifies through stwo's LIFTED protocol \
         at MOBILE blowup-4; corrupted witness rejected. The degree-flatten idiom holds."
    );
}
