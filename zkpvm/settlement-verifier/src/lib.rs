//! Verify-only Poseidon2-over-M31 stwo verifier — the on-chain settlement
//! verifier for native recursion.
//!
//! The native-recursion settlement verifier — stwo's `verify()` driven by a
//! custom Poseidon2-M31 Merkle channel, plus the in-AIR constraint evaluation
//! the verifier re-runs at the OODS point — built for `wasm32-unknown-unknown`
//! AND the JAM PVM (`riscv64em-javm`) target with NO blst and NO rayon. It
//! executes and ACCEPTS real proofs on the PVM (see `zkpvm/tests/settle_run.rs`).
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
//! Round constants are SYNCED from the prover's canonical Grain-LFSR arrays
//! (`zkpvm/src/poseidon2/mod.rs`), so this verifier accepts REAL proofs — they
//! must stay byte-identical to the prover's or every honest proof is rejected.
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
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator};

// ── Poseidon2-over-M31 parameters (width 16; eprint 2023/323 §5) ──────────

pub const N_STATE: usize = 16;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const RATE: usize = 8;

/// Trace columns per permutation instance (16 initial-state cols + 3 S-box
/// helper cols per S-box).  Kept in sync with [`eval_permutation`].
pub const N_PERM_COLS: usize = N_STATE + FULL_ROUNDS * (N_STATE * 3) + N_PARTIAL_ROUNDS * 3;

// Width-16 M31 Poseidon2 round constants — SYNCED from the prover's source of
// truth, `zkpvm/src/poseidon2/mod.rs` (the canonical Grain-LFSR arrays pinned by
// `zkpvm/tests/poseidon2_round_constants.rs`). They MUST stay byte-identical to
// the prover's, or this verifier rejects every honest proof.
pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; FULL_ROUNDS] = [
    [
        BaseField::from_u32_unchecked(1988864850),
        BaseField::from_u32_unchecked(1893772157),
        BaseField::from_u32_unchecked(1025928330),
        BaseField::from_u32_unchecked(1839472709),
        BaseField::from_u32_unchecked(1611656994),
        BaseField::from_u32_unchecked(1104858731),
        BaseField::from_u32_unchecked(1694088660),
        BaseField::from_u32_unchecked(1564660990),
        BaseField::from_u32_unchecked(1991332205),
        BaseField::from_u32_unchecked(1875486487),
        BaseField::from_u32_unchecked(1890340790),
        BaseField::from_u32_unchecked(1658614),
        BaseField::from_u32_unchecked(582370530),
        BaseField::from_u32_unchecked(528029397),
        BaseField::from_u32_unchecked(1196956642),
        BaseField::from_u32_unchecked(655401251),
    ],
    [
        BaseField::from_u32_unchecked(1652877415),
        BaseField::from_u32_unchecked(26032894),
        BaseField::from_u32_unchecked(1576640243),
        BaseField::from_u32_unchecked(1277052539),
        BaseField::from_u32_unchecked(1450142396),
        BaseField::from_u32_unchecked(697623591),
        BaseField::from_u32_unchecked(1401580866),
        BaseField::from_u32_unchecked(1568404175),
        BaseField::from_u32_unchecked(2145004971),
        BaseField::from_u32_unchecked(265835716),
        BaseField::from_u32_unchecked(1183985610),
        BaseField::from_u32_unchecked(1031234465),
        BaseField::from_u32_unchecked(436012490),
        BaseField::from_u32_unchecked(172735299),
        BaseField::from_u32_unchecked(352802897),
        BaseField::from_u32_unchecked(1032863094),
    ],
    [
        BaseField::from_u32_unchecked(757665783),
        BaseField::from_u32_unchecked(1082171296),
        BaseField::from_u32_unchecked(1507509996),
        BaseField::from_u32_unchecked(309929890),
        BaseField::from_u32_unchecked(1807683232),
        BaseField::from_u32_unchecked(43258895),
        BaseField::from_u32_unchecked(611592566),
        BaseField::from_u32_unchecked(1854193793),
        BaseField::from_u32_unchecked(575164234),
        BaseField::from_u32_unchecked(894217817),
        BaseField::from_u32_unchecked(72613857),
        BaseField::from_u32_unchecked(1061659596),
        BaseField::from_u32_unchecked(8921166),
        BaseField::from_u32_unchecked(1617355017),
        BaseField::from_u32_unchecked(998001536),
        BaseField::from_u32_unchecked(1800758877),
    ],
    [
        BaseField::from_u32_unchecked(1002748055),
        BaseField::from_u32_unchecked(1935405944),
        BaseField::from_u32_unchecked(1351462722),
        BaseField::from_u32_unchecked(411368491),
        BaseField::from_u32_unchecked(1913975372),
        BaseField::from_u32_unchecked(1956167178),
        BaseField::from_u32_unchecked(442558016),
        BaseField::from_u32_unchecked(855898408),
        BaseField::from_u32_unchecked(699687798),
        BaseField::from_u32_unchecked(1553382248),
        BaseField::from_u32_unchecked(1708169125),
        BaseField::from_u32_unchecked(490049183),
        BaseField::from_u32_unchecked(1251643415),
        BaseField::from_u32_unchecked(1193594742),
        BaseField::from_u32_unchecked(880473871),
        BaseField::from_u32_unchecked(511174042),
    ],
    [
        BaseField::from_u32_unchecked(1460209171),
        BaseField::from_u32_unchecked(530850056),
        BaseField::from_u32_unchecked(398192464),
        BaseField::from_u32_unchecked(536338716),
        BaseField::from_u32_unchecked(75179210),
        BaseField::from_u32_unchecked(1309934197),
        BaseField::from_u32_unchecked(1335920373),
        BaseField::from_u32_unchecked(127611036),
        BaseField::from_u32_unchecked(291093831),
        BaseField::from_u32_unchecked(1832379621),
        BaseField::from_u32_unchecked(123571662),
        BaseField::from_u32_unchecked(303176864),
        BaseField::from_u32_unchecked(2137685056),
        BaseField::from_u32_unchecked(1759609530),
        BaseField::from_u32_unchecked(1418928155),
        BaseField::from_u32_unchecked(71608334),
    ],
    [
        BaseField::from_u32_unchecked(6616262),
        BaseField::from_u32_unchecked(1684515814),
        BaseField::from_u32_unchecked(1721194338),
        BaseField::from_u32_unchecked(720801691),
        BaseField::from_u32_unchecked(878392254),
        BaseField::from_u32_unchecked(460379263),
        BaseField::from_u32_unchecked(87930647),
        BaseField::from_u32_unchecked(940673483),
        BaseField::from_u32_unchecked(1136203256),
        BaseField::from_u32_unchecked(551499412),
        BaseField::from_u32_unchecked(256220454),
        BaseField::from_u32_unchecked(2007034235),
        BaseField::from_u32_unchecked(796124985),
        BaseField::from_u32_unchecked(410436345),
        BaseField::from_u32_unchecked(1705042586),
        BaseField::from_u32_unchecked(1286336446),
    ],
    [
        BaseField::from_u32_unchecked(1522340456),
        BaseField::from_u32_unchecked(1295296352),
        BaseField::from_u32_unchecked(309794713),
        BaseField::from_u32_unchecked(1772145068),
        BaseField::from_u32_unchecked(956898901),
        BaseField::from_u32_unchecked(2137070800),
        BaseField::from_u32_unchecked(988829146),
        BaseField::from_u32_unchecked(2059451359),
        BaseField::from_u32_unchecked(1846491684),
        BaseField::from_u32_unchecked(1105442551),
        BaseField::from_u32_unchecked(1236497773),
        BaseField::from_u32_unchecked(1452000568),
        BaseField::from_u32_unchecked(549485016),
        BaseField::from_u32_unchecked(385992492),
        BaseField::from_u32_unchecked(1987107948),
        BaseField::from_u32_unchecked(1514377269),
    ],
    [
        BaseField::from_u32_unchecked(2090065934),
        BaseField::from_u32_unchecked(1444920141),
        BaseField::from_u32_unchecked(293113979),
        BaseField::from_u32_unchecked(41120774),
        BaseField::from_u32_unchecked(855319793),
        BaseField::from_u32_unchecked(1663284746),
        BaseField::from_u32_unchecked(1789994008),
        BaseField::from_u32_unchecked(1120509162),
        BaseField::from_u32_unchecked(358222743),
        BaseField::from_u32_unchecked(1406256810),
        BaseField::from_u32_unchecked(735183687),
        BaseField::from_u32_unchecked(664485235),
        BaseField::from_u32_unchecked(1331641456),
        BaseField::from_u32_unchecked(38121324),
        BaseField::from_u32_unchecked(595810771),
        BaseField::from_u32_unchecked(1234594393),
    ],
];
pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] = [
    BaseField::from_u32_unchecked(2139014335),
    BaseField::from_u32_unchecked(69309039),
    BaseField::from_u32_unchecked(1368974953),
    BaseField::from_u32_unchecked(886780232),
    BaseField::from_u32_unchecked(1130937085),
    BaseField::from_u32_unchecked(1718115455),
    BaseField::from_u32_unchecked(2027103386),
    BaseField::from_u32_unchecked(1612216449),
    BaseField::from_u32_unchecked(1994053242),
    BaseField::from_u32_unchecked(110146615),
    BaseField::from_u32_unchecked(514413329),
    BaseField::from_u32_unchecked(1088763546),
    BaseField::from_u32_unchecked(955319292),
    BaseField::from_u32_unchecked(488794657),
];

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

// `StarkProof<H>`'s derive bounds require `H: Serialize + Deserialize`, but the
// hasher VALUE is never serialized — only `H::Hash` (the committed roots) is. So
// these are dummy round-trippable impls (serialize 0 fields, deserialize to
// `default()`), byte-identical to the prover's `zkpvm::poseidon2::P2MerkleHasher`
// so a `StarkProof` produced there decodes here.
impl serde::Serialize for P2MerkleHasher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::ser::SerializeStruct::end(serializer.serialize_struct("P2MerkleHasher", 0)?)
    }
}
impl<'de> serde::Deserialize<'de> for P2MerkleHasher {
    fn deserialize<D: serde::Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::default())
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
/// decommit + OODS composition re-eval) for the custom M31-algebraic stack.
pub fn verify_segment(
    components: &[&dyn Component],
    channel: &mut Poseidon2M31Channel,
    commitment_scheme: &mut CommitmentSchemeVerifier<P2MerkleChannel>,
    proof: StarkProof<P2MerkleHasher>,
) -> Result<(), VerificationError> {
    verify::<P2MerkleChannel>(components, channel, commitment_scheme, proof)
}

// ── A concrete end-to-end settlement verify (proof bytes → accept/reject) ──
//
// The trivial settlement AIR `x·(x−1)=0`: a single boolean main column. Its
// constraint count is irrelevant to verify COST (FRI verify + Poseidon2 Merkle
// decommit + OODS dominate, independent of the AIR), so it is a representative
// stand-in for measuring on-chain settlement-verify cycles without carrying the
// full 31-chip segment AIR. MUST stay identical to the prover-side `BoolEval`
// in `zkpvm/tests/settle_fixture.rs` (same `FIXTURE_LOG`, same constraint), or
// the verifier replays a different AIR and rejects the honest proof.

/// Trace log-size of the embedded settlement-proof fixture.
pub const FIXTURE_LOG: u32 = 5;

struct BoolEval;
impl FrameworkEval for BoolEval {
    fn log_size(&self) -> u32 {
        FIXTURE_LOG
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        FIXTURE_LOG + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        eval.add_constraint(x.clone() * (x - E::F::one()));
        eval
    }
}

/// Deserialize a postcard-encoded settlement proof and verify it against the
/// embedded AIR + MOBILE config. `Ok(())` iff valid; `Err(())` on a decode
/// failure or a verification rejection (the settlement bin maps this to its
/// halt code). This is the full M31-algebraic verify the PVM run measures.
pub fn verify_settlement_proof(bytes: &[u8]) -> Result<(), ()> {
    let proof: StarkProof<P2MerkleHasher> = postcard::from_bytes(bytes).map_err(|_| ())?;
    let config = mobile_config();
    let component = FrameworkComponent::new(
        &mut TraceLocationAllocator::default(),
        BoolEval,
        SecureField::default(),
    );
    let channel = &mut Poseidon2M31Channel::default();
    let mut cs = CommitmentSchemeVerifier::<P2MerkleChannel>::new(config);
    // Replay the prover's 2-tree commitment transcript (preprocessed + main);
    // `verify` handles the interaction (logup) tree internally.
    let sizes = component.trace_log_degree_bounds();
    cs.commit(proof.commitments[0], &sizes[0], channel);
    cs.commit(proof.commitments[1], &sizes[1], channel);
    verify_segment(&[&component as &dyn Component], channel, &mut cs, proof).map_err(|_| ())
}

// ── Single-core atomic libcall shims for the JAM PVM (riscv64em-javm) ──────
//
// The PVM target is RV64EM with NO `a` (atomic) extension — JAVM does not decode
// `lr`/`sc`/`amo*`. We therefore set `max-atomic-width: 64` WITHOUT `+a`, so the
// few `core::sync::atomic` loads stwo's verify graph pulls in (via `foldhash`'s
// global seed and `tracing-core`'s callsite registration) lower to `__atomic_*`
// LIBCALLS instead of atomic instructions. JAVM is single-threaded, so an
// "atomic" load is just a plain load — these provide that. (Only the load widths
// the verify build actually references are defined; add others if a future link
// reports them undefined.) Scoped to the bare-metal PVM target so a host/wasm
// build never shadows the real `__atomic_*`.
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod pvm_atomic_shim {
    // Single-core ⇒ every "atomic" op is its plain non-atomic counterpart;
    // there is no other hart to race with. Signatures follow the GCC/LLVM
    // sized atomic-libcall ABI. Only the widths the verify build references
    // are defined (load/store/compare_exchange at 1 and 8 bytes); add more if
    // a future link reports them undefined.

    /// `T __atomic_load_N(const T* ptr, int memorder)`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_load_1(ptr: *const u8, _memorder: i32) -> u8 {
        core::ptr::read(ptr)
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_load_8(ptr: *const u64, _memorder: i32) -> u64 {
        core::ptr::read(ptr)
    }

    /// `void __atomic_store_N(T* ptr, T val, int memorder)`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_store_1(ptr: *mut u8, val: u8, _memorder: i32) {
        core::ptr::write(ptr, val)
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_store_8(ptr: *mut u64, val: u64, _memorder: i32) {
        core::ptr::write(ptr, val)
    }

    /// `bool __atomic_compare_exchange_N(T* ptr, T* expected, T desired,
    ///  int success_memorder, int failure_memorder)` — on single-core the
    /// load-compare-store cannot be interrupted by another hart, so the plain
    /// sequence IS the atomic CAS.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_compare_exchange_1(
        ptr: *mut u8,
        expected: *mut u8,
        desired: u8,
        _success: i32,
        _failure: i32,
    ) -> bool {
        let cur = core::ptr::read(ptr);
        if cur == core::ptr::read(expected) {
            core::ptr::write(ptr, desired);
            true
        } else {
            core::ptr::write(expected, cur);
            false
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_compare_exchange_8(
        ptr: *mut u64,
        expected: *mut u64,
        desired: u64,
        _success: i32,
        _failure: i32,
    ) -> bool {
        let cur = core::ptr::read(ptr);
        if cur == core::ptr::read(expected) {
            core::ptr::write(ptr, desired);
            true
        } else {
            core::ptr::write(expected, cur);
            false
        }
    }

    /// `T __atomic_exchange_N(T* ptr, T val, int memorder) -> old` (the spin
    /// lock's lock/unlock primitive).
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_exchange_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, val);
        old
    }

    /// `T __atomic_fetch_or_N(T* ptr, T val, int memorder) -> old`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_fetch_or_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, old | val);
        old
    }

    /// `T __atomic_fetch_and_N(T* ptr, T val, int memorder) -> old`.
    #[no_mangle]
    pub unsafe extern "C" fn __atomic_fetch_and_1(ptr: *mut u8, val: u8, _memorder: i32) -> u8 {
        let old = core::ptr::read(ptr);
        core::ptr::write(ptr, old & val);
        old
    }
}
