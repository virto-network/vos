#![allow(dead_code)]
//! Shared Poseidon2-over-M31 primitives for the native-recursion verifier-AIR
//! build (P3+).
//!
//! Consolidates the pieces the recursion foundation tests previously re-inlined
//! (the width-16 permutation, the M31-algebraic `MerkleHasherLifted`, and the
//! Poseidon2-M31 Fiat-Shamir channel — see `poseidon2_pcs_spike.rs`,
//! `poseidon2_chip_degree2.rs`, `poseidon2_m31_channel.rs`) PLUS the new
//! machinery a **cross-component (PRODUCER/CONSUMER) logup** circuit needs on
//! stwo's `CpuBackend`:
//!
//! - [`eval_permutation`] — the degree-2 flattened permutation as a *reusable*
//!   constraint fragment that returns its `(input[16], output[16])` masks, so a
//!   producer chip can emit the compression I/O into a relation.
//! - [`Poseidon2CompressionRelation`] — the 24-wide `(left‖right ‖ parent[8])`
//!   relation a `hash_children` PRODUCER fills and a `MerkleDecommit`-style
//!   CONSUMER drains.
//! - [`to_cpu`] — transplants a SIMD-generated logup interaction trace (stwo's
//!   `LogupTraceGenerator` is SimdBackend-only) into the `CpuBackend` columns
//!   the custom Poseidon2-M31 commitment scheme proves over. SimdBackend column
//!   *arithmetic* is always available; only the per-hasher `MerkleOpsLifted`
//!   commitment ops are not, which is why the proof itself rides `CpuBackend`.
//!
//! Round constants are the example's PLACEHOLDER `1234` (same as the foundation
//! tests): the protocol/degree/logup plumbing is independent of constant
//! quality, and vetted width-16 M31 constants are a documented P1 follow-up.

use std::cell::RefCell;
use std::ops::{Add, AddAssign, Mul, Sub};
use std::rc::Rc;

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::hash::Hash;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::{BackendForChannel, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::{EvalAtRow, relation};

// ── Poseidon2-over-M31 parameters (width 16; eprint 2023/323 §5) ──────────

pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const RATE: usize = 8;

/// Trace columns per permutation instance: 16 initial-state cols + 3 S-box
/// helper cols (y2,y4,out) per state element per full round + 3 per partial
/// round (only state[0] gets the S-box).
pub const N_PERM_COLS: usize = N_STATE + FULL_ROUNDS * (N_STATE * 3) + N_PARTIAL_ROUNDS * 3;

// Placeholder constants (P1 swaps in vetted width-16 M31 constants). Their value
// is independent of the protocol/degree/logup plumbing exercised here.
pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; FULL_ROUNDS];
pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

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

/// 2-to-1 node compression (the `hash_children` core): `parent[8] =
/// first8(permute(left[8] ‖ right[8]))`.
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

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct P2Hash(pub [BaseField; 8]);

impl std::fmt::Display for P2Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// Which channel op produced a recorded permutation — pins the per-row op type
/// the in-AIR [`ChannelChip`](../channel_chip.rs) replay reconstructs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermKind {
    /// A sponge absorption step (one RATE chunk mixed in, digest advanced).
    Absorb,
    /// A squeeze step (digest + `n_draws` + `DRAW_DOMAIN` → fresh challenge).
    Squeeze,
    /// One of `verify_pow_nonce`'s two permutations (does NOT advance digest).
    Pow,
}

/// One width-16 permutation as the transcript drove it: its full input + output
/// state and which op invoked it.  The ground truth the channel-replay AIR must
/// reproduce row-for-row (see the host-replay gate in `channel_chip.rs`).
///
/// `first_chunk` is `false` only for the continuation chunks of a multi-chunk
/// `absorb` (where the rate half carries the previous chunk's permuted state);
/// it is `true` for a fresh absorb's first chunk, every squeeze, and both pow
/// permutations.  The replay AIR uses it to drive the `is_cont` selector.
#[derive(Clone, Copy, Debug)]
pub struct PermRecord {
    pub kind: PermKind,
    pub input: [BaseField; N_STATE],
    pub output: [BaseField; N_STATE],
    pub first_chunk: bool,
}

/// A sponge transcript over the width-16 Poseidon2-M31 permutation, mirroring
/// `Poseidon252Channel`: an 8-M31 `digest` + an `n_draws` counter for squeeze
/// freshness.  Deterministic, so prover and verifier agree by construction.
///
/// When a `recorder` is attached (via [`Poseidon2M31Channel::recording`]) every
/// permutation the transcript performs is appended to it, in caller order —
/// this is how the channel-replay AIR pins the exact op sequence the native
/// stwo verifier drives.  Default (no recorder) is zero-overhead.
#[derive(Clone, Debug, Default)]
pub struct Poseidon2M31Channel {
    digest: [BaseField; 8],
    n_draws: u32,
    recorder: Option<Rc<RefCell<Vec<PermRecord>>>>,
}

const DRAW_DOMAIN: u32 = 3;

impl Poseidon2M31Channel {
    /// A fresh channel that records every permutation it performs into the
    /// shared buffer.  Clones share the buffer, so a channel handed to
    /// `verify()` records the whole verifier transcript.
    pub fn recording(recorder: Rc<RefCell<Vec<PermRecord>>>) -> Self {
        Self {
            digest: [BaseField::zero(); 8],
            n_draws: 0,
            recorder: Some(recorder),
        }
    }

    /// Permute `state` in place, recording `(kind, input, output, first_chunk)`
    /// when a recorder is attached.  Takes `&self` so `verify_pow_nonce` can
    /// record too.
    fn rec_permute(&self, kind: PermKind, first_chunk: bool, state: &mut [BaseField; N_STATE]) {
        let input = *state;
        permute(state);
        if let Some(rec) = &self.recorder {
            rec.borrow_mut().push(PermRecord {
                kind,
                input,
                output: *state,
                first_chunk,
            });
        }
    }

    fn update_digest(&mut self, new_digest: [BaseField; 8]) {
        self.digest = new_digest;
        self.n_draws = 0;
    }

    fn absorb(&mut self, values: &[BaseField]) {
        let mut state = [BaseField::zero(); N_STATE];
        state[..8].copy_from_slice(&self.digest);
        if values.is_empty() {
            self.rec_permute(PermKind::Absorb, true, &mut state);
        } else {
            for (ci, chunk) in values.chunks(RATE).enumerate() {
                for (i, v) in chunk.iter().enumerate() {
                    state[8 + i] += *v;
                }
                self.rec_permute(PermKind::Absorb, ci == 0, &mut state);
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
        self.rec_permute(PermKind::Squeeze, true, &mut state);
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
        self.rec_permute(PermKind::Pow, true, &mut s);
        let mut s2 = [BaseField::zero(); N_STATE];
        s2[..8].copy_from_slice(&s[..8]);
        s2[8] = BaseField::reduce(nonce & 0xFFFF_FFFF);
        s2[9] = BaseField::reduce(nonce >> 32);
        self.rec_permute(PermKind::Pow, true, &mut s2);
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

/// The one orphan-legal marker the custom channel needs: every super-bound of
/// `BackendForChannel<P2MerkleChannel>` is blanket-satisfied on `CpuBackend`;
/// legal because the trait's type parameter (`P2MerkleChannel`) is local.
impl BackendForChannel<P2MerkleChannel> for CpuBackend {}

// ── Degree-2 permutation AIR (the shared verifier-AIR workhorse) ──────────

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

/// Constrain one full width-16 Poseidon2 permutation, reading the 16 initial
/// masks then all the S-box helper masks in the exact order
/// [`record_permutation`] writes them.  Returns `(input[16], output[16])` so a
/// caller can bind the compression I/O into a relation.
pub fn eval_permutation<E: EvalAtRow>(eval: &mut E) -> ([E::F; N_STATE], [E::F; N_STATE]) {
    let init: [E::F; N_STATE] = std::array::from_fn(|_| eval.next_trace_mask());
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

/// Host recorder producing the per-row column values in EXACTLY the order
/// [`eval_permutation`] reads them.  Output length is [`N_PERM_COLS`].
pub fn record_permutation(init: [BaseField; N_STATE]) -> Vec<BaseField> {
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

    let mut state = init;
    let mut cols = Vec::with_capacity(N_PERM_COLS);
    cols.extend_from_slice(&state);
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
    debug_assert_eq!(cols.len(), N_PERM_COLS);
    cols
}

// ── The cross-chip compression relation ───────────────────────────────────

/// `(left[8] ‖ right[8] ‖ parent[8])` = 24 M31s: a `hash_children` PRODUCER
/// (the permutation chip) emits one per row with +1; a `MerkleDecommit`-style
/// CONSUMER drains the same tuple with −1, so it trusts `parent == H(left,
/// right)` without re-running the 442-column permutation itself.
pub const COMPRESSION_TUPLE_LEN: usize = 24;
relation!(Poseidon2CompressionRelation, COMPRESSION_TUPLE_LEN);

// ── Configs + SIMD→CpuBackend transplant ──────────────────────────────────

/// MOBILE: blowup 4 (log_blowup_factor=2), 38 queries, 20-bit PoW.
pub fn mobile_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    }
}

/// Transplant SimdBackend evaluations (what stwo's `LogupTraceGenerator`
/// returns, and the convenient backend for trace generation) into the
/// `CpuBackend` columns the Poseidon2-M31 commitment scheme proves over.  Pure
/// value copy — the order/domain are preserved.
pub fn to_cpu(
    evals: &[CircleEvaluation<
        stwo::prover::backend::simd::SimdBackend,
        BaseField,
        BitReversedOrder,
    >],
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    evals.iter().map(|e| e.to_cpu()).collect()
}
