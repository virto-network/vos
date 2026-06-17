//! Verify-only Poseidon2-over-M31 stwo verifier — the P4.3 buildability spike.
//!
//! This crate exists to answer ONE question: does the native-recursion
//! settlement verifier — stwo's `verify()` driven by a custom Poseidon2-M31
//! Merkle channel, plus the in-AIR constraint evaluation the verifier re-runs
//! at the OODS point — compile for `wasm32-unknown-unknown` AND the PVM
//! (`riscv64em-javm`) target with NO blst and NO rayon?
//!
//! It carries only the VERIFY side of the recursion stack (promoted from the
//! prover-side `zkpvm/tests/recursion_common/mod.rs`):
//!   * the width-16 Poseidon2-M31 permutation + the `MerkleHasherLifted`
//!     (`P2MerkleHasher`) the inner proofs are committed under,
//!   * the Poseidon2-M31 Fiat-Shamir `Channel` (`Poseidon2M31Channel`) + its
//!     `MerkleChannel` (`P2MerkleChannel`),
//!   * the degree-2 flattened permutation AIR fragment (`eval_permutation`) the
//!     verifier re-evaluates at OODS — generic over `EvalAtRow`, so it is the
//!     same code path a join-AIR `FrameworkEval` runs under `verify()`.
//!
//! It DROPS everything prover-side: the `BackendForChannel`/`CpuBackend`
//! commitment ops, the SIMD→CPU transplant, the host trace recorder, and any
//! `std`/`rayon`/`blst` dependency (the latter only ever entered transitively
//! via `javm`, which this crate does not depend on).
//!
//! Round constants are the foundation's placeholder `1234` — irrelevant to
//! buildability (the protocol/degree plumbing is constant-independent); vetted
//! width-16 M31 constants are the P1 follow-up.
#![no_std]
// AIR fill + the permutation are byte-position-indexed throughout (state[i],
// round-const tables); the index loops are the natural shape (same rationale as
// the parent `zkpvm` crate's lint config).  The `% RATE` sponge-padding form
// mirrors the prover-side source of truth.
#![allow(clippy::needless_range_loop, clippy::manual_is_multiple_of)]

extern crate alloc;

use alloc::vec::Vec;
use core::array::from_fn;
use core::ops::{Add, AddAssign, Mul, Sub};

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{verify, VerificationError};
use stwo_constraint_framework::EvalAtRow;

// ── Poseidon2-over-M31 parameters (width 16; eprint 2023/323 §5) ──────────

pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const RATE: usize = 8;

/// Trace columns per permutation instance (16 initial-state cols + 3 S-box
/// helper cols per S-box).  Kept in sync with [`eval_permutation`].
pub const N_PERM_COLS: usize = N_STATE + FULL_ROUNDS * (N_STATE * 3) + N_PARTIAL_ROUNDS * 3;

pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; FULL_ROUNDS];
pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

const DRAW_DOMAIN: u32 = 3;

// ── Linear layers (generic: BaseField for the host, E::F for constraints) ──

pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
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

pub fn apply_external_round_matrix<F>(state: &mut [F; 16])
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

pub fn apply_internal_round_matrix<F>(state: &mut [F; 16])
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

// ── Host permutation (used by the hasher + channel) ───────────────────────

fn pow5(x: BaseField) -> BaseField {
    let x2 = x * x;
    x2 * x2 * x
}

/// The Poseidon2-over-M31 permutation: 4 full → 14 partial → 4 full rounds.
pub fn permute(state: &mut [BaseField; N_STATE]) {
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

/// 2-to-1 node compression (the `hash_children` core).
pub fn hash_children_m31(left: &[BaseField; 8], right: &[BaseField; 8]) -> [BaseField; 8] {
    let mut state = [BaseField::zero(); N_STATE];
    state[..8].copy_from_slice(left);
    state[8..].copy_from_slice(right);
    permute(&mut state);
    let mut out = [BaseField::zero(); 8];
    out.copy_from_slice(&state[..8]);
    out
}

// ── M31-algebraic Merkle hasher (the de-risked PCS commitment) ────────────

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct P2Hash(pub [BaseField; 8]);

impl core::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P2Hash({:?})", self.0.map(|m| m.0))
    }
}
impl Hash for P2Hash {}

#[derive(Clone, Debug)]
pub struct P2MerkleHasher {
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
        P2Hash(hash_children_m31(&left.0, &right.0))
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

// ── Poseidon2-M31 Fiat-Shamir channel (no Blake2s on commit OR transcript) ─

/// A sponge transcript over the width-16 Poseidon2-M31 permutation, mirroring
/// `Poseidon252Channel`: an 8-M31 `digest` + an `n_draws` counter for squeeze
/// freshness.  Verify-side only — no recorder (that is prover/test
/// instrumentation).  Deterministic, so prover and verifier agree by
/// construction.
#[derive(Clone, Debug, Default)]
pub struct Poseidon2M31Channel {
    digest: [BaseField; 8],
    n_draws: u32,
}

impl Poseidon2M31Channel {
    fn update_digest(&mut self, new_digest: [BaseField; 8]) {
        self.digest = new_digest;
        self.n_draws = 0;
    }

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
        self.squeeze8().iter().map(|m| m.0).collect()
    }
}

#[derive(Default)]
pub struct P2MerkleChannel;
impl MerkleChannel for P2MerkleChannel {
    type C = Poseidon2M31Channel;
    type H = P2MerkleHasher;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.mix_root(root);
    }
}

// ── Degree-2 permutation AIR fragment (re-evaluated by verify() at OODS) ───

/// Flatten x^5 to three degree-2 constraints with witnessed intermediates.
pub fn sbox_flatten<E: EvalAtRow>(eval: &mut E, y: E::F) -> E::F {
    let y2 = eval.next_trace_mask();
    eval.add_constraint(y2.clone() - y.clone() * y.clone());
    let y4 = eval.next_trace_mask();
    eval.add_constraint(y4.clone() - y2.clone() * y2.clone());
    let out = eval.next_trace_mask();
    eval.add_constraint(out.clone() - y4 * y);
    out
}

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

/// Constrain one full width-16 Poseidon2 permutation.  Returns
/// `(input[16], output[16])`.  This is the verifier-AIR's row driver — the
/// verifier re-runs it at the OODS point inside `verify()`.
pub fn eval_permutation<E: EvalAtRow>(eval: &mut E) -> ([E::F; N_STATE], [E::F; N_STATE]) {
    let init: [E::F; N_STATE] = from_fn(|_| eval.next_trace_mask());
    let mut state = init.clone();
    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(eval, &mut state, &EXTERNAL_ROUND_CONSTS[round]);
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += INTERNAL_ROUND_CONSTS[round];
        apply_internal_round_matrix(&mut state);
        state[0] = sbox_flatten(eval, state[0].clone());
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(
            eval,
            &mut state,
            &EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS],
        );
    }
    (init, state)
}

// ── Configs + the verify entry (forces monomorphization of the verify path) ─

/// MOBILE: blowup 4 (log_blowup_factor=2), 38 queries, 20-bit PoW.
pub fn mobile_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

/// The settlement verify entry: run stwo's `verify()` driven by the custom
/// Poseidon2-M31 Merkle channel.  Concrete in `P2MerkleChannel`, so building
/// this crate for a target MONOMORPHIZES the entire verify path (FRI + Merkle
/// decommit + OODS composition re-eval) for the custom M31-algebraic stack —
/// the buildability proof the P4.3 gate asks for.
pub fn verify_segment(
    components: &[&dyn Component],
    channel: &mut Poseidon2M31Channel,
    commitment_scheme: &mut CommitmentSchemeVerifier<P2MerkleChannel>,
    proof: StarkProof<P2MerkleHasher>,
) -> Result<(), VerificationError> {
    verify::<P2MerkleChannel>(components, channel, commitment_scheme, proof)
}
