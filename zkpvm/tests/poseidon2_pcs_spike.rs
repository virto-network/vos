//! Recursion de-risk spike: instantiate stwo's PCS with a custom
//! **Poseidon2-over-M31** Merkle hasher and prove+verify one toy AIR through
//! it, end-to-end, on `CpuBackend`.
//!
//! ## Why this exists
//!
//! Native STARK-verifier-in-STARK recursion needs the inner proof committed
//! under an *M31-algebraic* hash (so the verifier's Merkle-path checks are
//! cheap to re-express as constraints), not the production Blake2s PCS. The
//! open question this spike answers is the foundation of that whole effort:
//! **can the pinned stwo (rev e1286720) be instantiated with a custom
//! M31-algebraic `MerkleHasher`, produce a proof, and verify it?** If not, the
//! native-recursion path is blocked at the base and the answer is "ship the
//! manifest delivery and wait for upstream". If yes, the foundation is sound.
//!
//! ## What it proves (and does NOT)
//!
//! GREEN here means stwo's generic PCS round-trips a real proof whose Merkle
//! commitments are produced by a custom Poseidon2-M31 sponge — the plumbing
//! works. It deliberately does NOT establish security: the permutation uses the
//! example AIR's *placeholder* round constants (`1234`), which make a
//! deterministic-but-not-collision-resistant `f: M31^16 -> M31^16`. Soundness
//! (vetted width-16 M31 constants, reconciling the internal-diagonal
//! convention, and an M31-algebraic Fiat-Shamir transcript) is the follow-on
//! work, out of scope for "does the plumbing work".
//!
//! ## Design (from the scoping investigation)
//!
//! - The prover rides the **lifted** VCS: `prove()` needs
//!   `CpuBackend: BackendForChannel<MC>` where `MC::H: MerkleHasherLifted`. On
//!   `CpuBackend` every backend op (`MerkleOpsLifted`, `GrindOps`, `ColumnOps`,
//!   `PackLeavesOps`) is a **blanket** impl, so a custom hasher needs zero
//!   backend code — only one orphan-legal marker `impl BackendForChannel<..>
//!   for CpuBackend {}` (the trait's type-parameter is our local channel type).
//! - The Fiat-Shamir transcript reuses the existing `Blake2sM31Channel` (PCS
//!   correctness does not require an algebraic transcript; only later recursion
//!   soundness does). Only the **Merkle commitment** hash is Poseidon2-M31 here.
//! - The toy AIR is genuinely **degree-1** (`c = a + b`), the conservative
//!   choice for the lifted protocol.
//!
//! Run: `cargo test -p zkpvm --test poseidon2_pcs_spike -- --nocapture`

use std::ops::{Add, AddAssign, Mul, Sub};

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel, MerkleChannel};
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::verify;
use stwo::prover::backend::{BackendForChannel, Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

// ── Poseidon2-over-M31 permutation (width 16) ────────────────────────────
//
// Copied from the stwo example AIR `crates/examples/src/poseidon/mod.rs`
// (eprint 2023/323, §5): 8 full + 14 partial rounds, M4 MDS external matrix,
// internal diagonal mu_i = 2^{i+1}+1, S-box x^5. The examples crate is not a
// dependency of zkpvm, so the round functions are inlined here. The round
// constants are the example's PLACEHOLDER value (`1234`) — see the module doc.

const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 14;
const N_HALF_FULL_ROUNDS: usize = 4;

const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; 2 * N_HALF_FULL_ROUNDS];
const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

/// M4 MDS matrix (eprint 2023/323 §5.1).
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

/// External round matrix circ(2*M4, M4, M4, M4) (eprint 2023/323 §5.1).
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

/// Internal round matrix, diagonal mu_i = 2^{i+1}+1 (eprint 2023/323 §5.2).
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

/// S-box x^5.
fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

/// The Poseidon2-over-M31 permutation: 4 full → 14 partial → 4 full rounds.
/// Mirrors the example AIR's `gen_trace` round loop without the trace writes.
fn permute(state: &mut [BaseField; N_STATE]) {
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round][i];
        }
        apply_external_round_matrix(state);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += INTERNAL_ROUND_CONSTS[round];
        apply_internal_round_matrix(state);
        state[0] = pow5(state[0]);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
        }
        apply_external_round_matrix(state);
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
    }
}

// ── Custom hash output type ──────────────────────────────────────────────

/// 8-element M31 digest (the rate half of the 16-wide sponge state).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
struct P2Hash([BaseField; 8]);

impl std::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P2Hash[")?;
        for (i, v) in self.0.iter().enumerate() {
            if i != 0 {
                write!(f, ",")?;
            }
            write!(f, "{}", v.0)?;
        }
        write!(f, "]")
    }
}

impl Hash for P2Hash {}

// ── Custom lifted Merkle hasher (the thing under test) ───────────────────

const RATE: usize = 8;

/// A stateful Poseidon2-over-M31 sponge implementing stwo's `MerkleHasherLifted`
/// (the trait the lifted PCS commits with). Mirrors `Poseidon252MerkleHasher`'s
/// buffer/absorb/finalize structure, but absorbs raw M31 (no field packing) and
/// uses the width-16 M31 permutation above.
#[derive(Clone, Debug)]
struct P2MerkleHasher {
    state: [BaseField; N_STATE],
    buffer: Vec<BaseField>,
}

impl Default for P2MerkleHasher {
    fn default() -> Self {
        Self {
            state: [BaseField::zero(); N_STATE],
            buffer: Vec::new(),
        }
    }
}

impl MerkleHasherLifted for P2MerkleHasher {
    type Hash = P2Hash;

    /// 2-to-1 compression: load the two child digests into the 16-wide state,
    /// permute, take the rate half as the parent.
    fn hash_children((left, right): (P2Hash, P2Hash)) -> P2Hash {
        let mut state = [BaseField::zero(); N_STATE];
        state[..8].copy_from_slice(&left.0);
        state[8..].copy_from_slice(&right.0);
        permute(&mut state);
        let mut out = [BaseField::zero(); 8];
        out.copy_from_slice(&state[..8]);
        P2Hash(out)
    }

    /// Absorb column values into the sponge. Buffers across calls and only
    /// drains FULL rate-sized blocks, so the digest depends solely on the
    /// concatenated leaf values, not on how the PCS chunks `update_leaf`.
    fn update_leaf(&mut self, column_values: &[BaseField]) {
        self.buffer.extend_from_slice(column_values);
        while self.buffer.len() >= RATE {
            for i in 0..RATE {
                self.state[i] += self.buffer[i];
            }
            permute(&mut self.state);
            self.buffer.drain(0..RATE);
        }
    }

    /// Pad the remaining (< RATE) buffer with a `1` domain separator then zeros,
    /// absorb the final block, permute, and emit the rate half.
    fn finalize(mut self) -> P2Hash {
        self.buffer.push(BaseField::one());
        while self.buffer.len() % RATE != 0 {
            self.buffer.push(BaseField::zero());
        }
        let mut i = 0;
        while i < self.buffer.len() {
            for j in 0..RATE {
                self.state[j] += self.buffer[i + j];
            }
            permute(&mut self.state);
            i += RATE;
        }
        let mut out = [BaseField::zero(); 8];
        out.copy_from_slice(&self.state[..8]);
        P2Hash(out)
    }
}

// ── Custom MerkleChannel (Poseidon2-M31 commitment + reused transcript) ──

/// Ties the Poseidon2-M31 Merkle hasher to a Fiat-Shamir transcript. The
/// transcript reuses the stock `Blake2sM31Channel` — only the Merkle commitment
/// is Poseidon2-M31 in this de-risk spike (an algebraic transcript is the
/// separate follow-on for full recursion soundness).
#[derive(Default)]
struct P2MerkleChannel;

impl MerkleChannel for P2MerkleChannel {
    type C = Blake2sM31Channel;
    type H = P2MerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        let words: [u32; 8] = root.0.map(|m| m.0);
        channel.mix_u32s(&words);
    }
}

// The one orphan-legal marker the custom channel needs: all of
// `BackendForChannel`'s super-bounds (MerkleOpsLifted<P2MerkleHasher> +
// GrindOps<Blake2sM31Channel> + Backend) are already blanket-satisfied on
// CpuBackend. Legal because the trait's type-parameter (P2MerkleChannel) is
// local to this crate, even though both the trait and CpuBackend are foreign.
impl BackendForChannel<P2MerkleChannel> for CpuBackend {}

// ── Toy degree-1 AIR: additive Fibonacci, c = a + b ──────────────────────

const FIB_LEN: usize = 16;

#[derive(Clone)]
struct AddFibEval {
    log_n_rows: u32,
}

impl FrameworkEval for AddFibEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree-1 constraint; +1 is a sound (slightly loose) upper bound.
        self.log_n_rows + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut a = eval.next_trace_mask();
        let mut b = eval.next_trace_mask();
        for _ in 2..FIB_LEN {
            let c = eval.next_trace_mask();
            eval.add_constraint(c.clone() - (a.clone() + b.clone()));
            a = b;
            b = c;
        }
        eval
    }
}

/// Build a degree-1 additive-Fibonacci trace: one length-`FIB_LEN` sequence per
/// row, `c = a + b`.
fn gen_addfib_trace(
    log_size: u32,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1usize << log_size;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = (0..FIB_LEN)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n_rows))
        .collect();
    for row in 0..n_rows {
        let mut a = BaseField::one();
        let mut b = BaseField::from_u32_unchecked(row as u32);
        trace[0].set(row, a);
        trace[1].set(row, b);
        for col in trace.iter_mut().take(FIB_LEN).skip(2) {
            let c = a + b;
            col.set(row, c);
            a = b;
            b = c;
        }
    }
    let domain = CanonicCoset::new(log_size).circle_domain();
    trace
        .into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect()
}

// ── The spike: prove + verify a toy AIR through the Poseidon2-M31 PCS ────

#[test]
fn poseidon2_m31_pcs_round_trip() {
    const LOG_N_ROWS: u32 = 4; // 2^4 rows — trivial on CpuBackend.

    let config = PcsConfig::default();
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // ---- Prove, committing every Merkle tree with the Poseidon2-M31 hasher.
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);

    // Mandatory (empty) preprocessed tree, then the trace tree.
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(Vec::new());
    tree_builder.commit(prover_channel);

    let trace = gen_addfib_trace(LOG_N_ROWS);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let component = FrameworkComponent::<AddFibEval>::new(
        &mut TraceLocationAllocator::default(),
        AddFibEval {
            log_n_rows: LOG_N_ROWS,
        },
        SecureField::zero(),
    );

    let proof =
        prove::<CpuBackend, P2MerkleChannel>(&[&component], prover_channel, commitment_scheme)
            .expect("prove through the Poseidon2-M31 PCS");

    // The commitments ARE Poseidon2-M31 digests (compile-time: StarkProof<P2MerkleHasher>),
    // and a real proof was produced. The prover commits preprocessed + trace +
    // composition-polynomial trees, so there are 3; the verifier re-commits the
    // first two and `verify` consumes the composition commitment itself.
    assert!(
        proof.commitments.len() >= 2,
        "expected at least preprocessed + trace commitments, got {}",
        proof.commitments.len()
    );

    // Verify with a fresh transcript (replays Fiat-Shamir from scratch). The
    // verifier re-derives Merkle roots through the SAME Poseidon2-M31 hasher and
    // checks decommitment paths against the proof's roots.
    let do_verify = |proof: stwo::core::proof::StarkProof<P2MerkleHasher>| {
        let verifier_channel = &mut Blake2sM31Channel::default();
        let mut verifier_scheme = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
        let sizes = component.trace_log_degree_bounds();
        verifier_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
        verifier_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
        verify(&[&component], verifier_channel, &mut verifier_scheme, proof)
    };

    // Positive: the honest proof verifies.
    do_verify(proof.clone()).expect("verify the Poseidon2-M31 PCS proof");

    // Negative: flip one M31 in the trace commitment root. The verifier mixes a
    // different root into the transcript and its decommitment no longer matches,
    // so it MUST reject — confirming the commitment binding runs through the
    // custom hasher rather than being vacuously accepted.
    let mut tampered = proof.clone();
    tampered.0.commitments[1].0[0] += BaseField::one();
    assert!(
        do_verify(tampered).is_err(),
        "a tampered Poseidon2-M31 commitment root must be rejected"
    );

    eprintln!(
        "poseidon2_m31_pcs_round_trip GREEN: stwo's lifted PCS proved+verified a \
         degree-1 AIR committed under a custom Poseidon2-over-M31 Merkle hasher \
         (CpuBackend). The native-recursion PCS foundation is plumbing-feasible."
    );
}
