//! A **Poseidon2-over-M31 Fiat-Shamir channel**: the transcript is M31-algebraic
//! end-to-end — NO Blake2s anywhere on the commit/transcript path. Combined with
//! a Poseidon2-M31 Merkle commitment it yields a fully M31-algebraic PCS whose
//! transcript hash is the same algebraic permutation as the Merkle hash, so a
//! verifier can replay the transcript in-circuit as Poseidon2 permutations
//! instead of Blake2s.
//!
//! ## Gate
//!
//! A toy AIR proves+verifies with the Poseidon2-M31 channel as the Fiat-Shamir
//! transcript AND a Poseidon2-M31 Merkle commitment — no Blake2s on either path
//! — plus channel-determinism checks (a fresh channel draws reproducibly; mixing
//! changes subsequent draws). The permutation here uses placeholder round
//! constants `1234`: this test exercises only the transcript PLUMBING, so prover
//! and verifier run the same channel and agree by construction regardless of
//! constant quality. The vetted width-16 M31 constants are pinned separately in
//! `poseidon2_round_constants.rs`.
//!
//! Run: `cargo test -p zkpvm --test poseidon2_m31_channel -- --nocapture`

use std::ops::{Add, AddAssign, Mul, Sub};

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
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

// ── Poseidon2-over-M31 permutation (width 16) ─────────────────────────────

const N_STATE: usize = 16;
const N_PARTIAL_ROUNDS: usize = 14;
const N_HALF_FULL_ROUNDS: usize = 4;
const RATE: usize = 8;

const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; 2 * N_HALF_FULL_ROUNDS];
const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

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

fn apply_external_round_matrix(state: &mut [BaseField; 16]) {
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ]);
    }
    for j in 0..4 {
        let s = state[j] + state[j + 4] + state[j + 8] + state[j + 12];
        for i in 0..4 {
            state[4 * i + j] += s;
        }
    }
}

fn apply_internal_round_matrix(state: &mut [BaseField; 16]) {
    let sum = state[1..].iter().copied().fold(state[0], |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = *s * BaseField::from_u32_unchecked(1 << (i + 1)) + sum;
    });
}

fn pow5(x: BaseField) -> BaseField {
    let x2 = x * x;
    x2 * x2 * x
}

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

// ── Poseidon2-M31 Merkle hasher (the PCS commitment) ──────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
struct P2Hash([BaseField; 8]);

impl std::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P2Hash({:?})", self.0.map(|m| m.0))
    }
}
impl Hash for P2Hash {}

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
    fn hash_children((left, right): (P2Hash, P2Hash)) -> P2Hash {
        let mut state = [BaseField::zero(); N_STATE];
        state[..8].copy_from_slice(&left.0);
        state[8..].copy_from_slice(&right.0);
        permute(&mut state);
        let mut out = [BaseField::zero(); 8];
        out.copy_from_slice(&state[..8]);
        P2Hash(out)
    }
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

// ── Poseidon2-M31 Fiat-Shamir channel ─────────────────────────────────────

/// A sponge transcript over the width-16 Poseidon2-M31 permutation, mirroring
/// `Poseidon252Channel`: an 8-M31 `digest` carried in the capacity half + an
/// `n_draws` counter for squeeze freshness. Mixing resets `n_draws`; draws use a
/// distinct domain tag so a draw can never alias a mix. Deterministic, so the
/// prover and verifier (both running this code) agree by construction.
#[derive(Clone, Debug, Default)]
struct Poseidon2M31Channel {
    digest: [BaseField; 8],
    n_draws: u32,
}

/// Domain tag occupying a capacity lane during a draw (mixes never set it).
const DRAW_DOMAIN: u32 = 3;

impl Poseidon2M31Channel {
    fn update_digest(&mut self, new_digest: [BaseField; 8]) {
        self.digest = new_digest;
        self.n_draws = 0;
    }

    /// Absorb `values`: `digest := first8(sponge(digest ‖ values))`. The rate
    /// half starts at 0 each call, so the result depends only on `(digest,
    /// values)` — a self-contained `H(digest, values)`, like Poseidon252's
    /// `poseidon_hash_many([digest, ..])`.
    fn absorb(&mut self, values: &[BaseField]) {
        let mut state = [BaseField::zero(); N_STATE];
        state[..8].copy_from_slice(&self.digest);
        if values.is_empty() {
            permute(&mut state);
        } else {
            for chunk in values.chunks(RATE) {
                for (i, v) in chunk.iter().enumerate() {
                    state[8 + i] += *v;
                }
                permute(&mut state);
            }
        }
        let mut d = [BaseField::zero(); 8];
        d.copy_from_slice(&state[..8]);
        self.update_digest(d);
    }

    /// Squeeze 8 M31s, domain-separated from mixing and freshened by `n_draws`.
    fn squeeze8(&mut self) -> [BaseField; 8] {
        let mut state = [BaseField::zero(); N_STATE];
        state[..8].copy_from_slice(&self.digest);
        state[8] = BaseField::reduce(self.n_draws as u64);
        state[9] = BaseField::reduce(DRAW_DOMAIN as u64);
        permute(&mut state);
        self.n_draws += 1;
        let mut out = [BaseField::zero(); 8];
        out.copy_from_slice(&state[..8]);
        out
    }

    fn mix_root(&mut self, root: P2Hash) {
        self.absorb(&root.0);
    }
}

impl Channel for Poseidon2M31Channel {
    const BYTES_PER_HASH: usize = 32;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        // H(H(digest, n_bits), nonce); accept if the first output limb has >=
        // n_bits trailing zeros (the prover grinds the nonce).
        let mut s = [BaseField::zero(); N_STATE];
        s[..8].copy_from_slice(&self.digest);
        s[8] = BaseField::reduce(n_bits as u64);
        permute(&mut s);
        let mut s2 = [BaseField::zero(); N_STATE];
        s2[..8].copy_from_slice(&s[..8]);
        s2[8] = BaseField::reduce(nonce & 0xFFFF_FFFF);
        s2[9] = BaseField::reduce(nonce >> 32);
        permute(&mut s2);
        s2[0].0.trailing_zeros() >= n_bits
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let m: Vec<BaseField> = data.iter().map(|&x| BaseField::reduce(x as u64)).collect();
        self.absorb(&m);
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let m: Vec<BaseField> = felts.iter().flat_map(|x| x.to_m31_array()).collect();
        self.absorb(&m);
    }

    fn mix_u64(&mut self, value: u64) {
        self.absorb(&[
            BaseField::reduce(value & 0xFFFF_FFFF),
            BaseField::reduce(value >> 32),
        ]);
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let f = self.squeeze8();
        SecureField::from_m31_array([f[0], f[1], f[2], f[3]])
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut out = Vec::with_capacity(n_felts);
        while out.len() < n_felts {
            let f = self.squeeze8();
            out.push(SecureField::from_m31_array([f[0], f[1], f[2], f[3]]));
            if out.len() < n_felts {
                out.push(SecureField::from_m31_array([f[4], f[5], f[6], f[7]]));
            }
        }
        out
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        // Each squeezed M31 is < 2^31, ample entropy for query positions.
        self.squeeze8().iter().map(|m| m.0).collect()
    }
}

#[derive(Default)]
struct P2MerkleChannel;
impl MerkleChannel for P2MerkleChannel {
    type C = Poseidon2M31Channel;
    type H = P2MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.mix_root(root);
    }
}

impl BackendForChannel<P2MerkleChannel> for CpuBackend {}

// ── Toy degree-1 AIR (additive Fibonacci) to isolate the channel ──────────

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

fn gen_trace(log_size: u32) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
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

#[test]
fn poseidon2_m31_channel_no_blake2s() {
    // ── Channel determinism / freshness (no proving) ──
    let mut a = Poseidon2M31Channel::default();
    let mut b = Poseidon2M31Channel::default();
    assert_eq!(
        a.draw_u32s(),
        b.draw_u32s(),
        "fresh channels draw identically"
    );
    let d1 = a.draw_secure_felt();
    let d2 = a.draw_secure_felt();
    assert_ne!(d1, d2, "successive draws differ (n_draws freshness)");
    let mut c = Poseidon2M31Channel::default();
    c.mix_u64(0x1111_2222_3333_4444);
    assert_ne!(
        c.draw_u32s(),
        Poseidon2M31Channel::default().draw_u32s(),
        "mixing changes subsequent draws"
    );

    // ── Prove + verify a toy AIR with NO Blake2s on commit OR transcript ──
    const LOG_N_ROWS: u32 = 4;
    let config = PcsConfig::default();
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Poseidon2M31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, P2MerkleChannel>::new(config, &twiddles);
    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(Vec::new());
    tb.commit(prover_channel);
    let mut tb = commitment_scheme.tree_builder();
    tb.extend_evals(gen_trace(LOG_N_ROWS));
    tb.commit(prover_channel);

    let component = FrameworkComponent::<AddFibEval>::new(
        &mut TraceLocationAllocator::default(),
        AddFibEval {
            log_n_rows: LOG_N_ROWS,
        },
        SecureField::zero(),
    );
    let proof =
        prove::<CpuBackend, P2MerkleChannel>(&[&component], prover_channel, commitment_scheme)
            .expect("prove with a Poseidon2-M31 commitment + Poseidon2-M31 transcript");

    let verifier_channel = &mut Poseidon2M31Channel::default();
    let mut verifier_scheme = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    verifier_scheme.commit(proof.commitments[0], &sizes[0], verifier_channel);
    verifier_scheme.commit(proof.commitments[1], &sizes[1], verifier_channel);
    verify(&[&component], verifier_channel, &mut verifier_scheme, proof)
        .expect("verify a fully M31-algebraic (no-Blake2s) proof");

    eprintln!(
        "poseidon2_m31_channel_no_blake2s GREEN: a toy AIR proves+verifies with a \
         Poseidon2-over-M31 Merkle commitment AND a Poseidon2-over-M31 Fiat-Shamir \
         transcript — no Blake2s anywhere. The recursion transcript foundation holds."
    );
}
