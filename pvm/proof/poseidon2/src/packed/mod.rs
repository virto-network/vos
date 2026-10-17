//! Sixteen Poseidon2 permutations at once, for the prover's hashing.
//!
//! [`permute_x16`] takes the states of sixteen permutations side by side:
//! `state[i][l]` is word `i` of permutation `l`. Every word must lie in
//! `[0, P]`, and every output word is canonical, in `[0, P)`. Each lane equals
//! [`crate::permute`] on that lane's state.
//!
//! The instruction set is chosen at compile time, as Stwo's `SimdBackend`
//! chooses its own: AVX-512F, else AVX2, else NEON, else the scalar
//! permutation lane by lane. Each vector form holds all sixteen lanes (one
//! 512-bit, two 256-bit or four 128-bit registers a word), so independent
//! lanes interleave in one pass.
//!
//! The vector arithmetic is adapted from Plonky3 at revision
//! `f98331687e47106a64ab82a77e2e1d0d66c9161b` (MIT or Apache-2.0; see each
//! module's header and `LICENSE-PLONKY3-MIT`). The arrangement below is
//! Plonky3's `Poseidon2Mersenne31<16>` on packed fields, written once over a
//! `Vector` each instruction set implements.

// Without vector instructions only the scalar fallback runs.
#![cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon"),
    )),
    allow(dead_code)
)]

use crate::{
    EXTERNAL_ROUND_CONSTS, FULL_ROUNDS, INTERNAL_DIAG_SHIFTS, INTERNAL_ROUND_CONSTS, M31,
    N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE,
};

/// The permutations [`permute_x16`] runs at once.
pub const LANES: usize = 16;

use crate::P;

/// Sixteen permutation states, word-major: `state[word][lane]`.
pub type States = [[u32; LANES]; N_STATE];

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
mod avx512;
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
use avx512::V16;

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
mod avx2;
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
use avx2::V16;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
use neon::V16;

/// Whether [`permute_x16`] runs on vectors: false where it falls back to the
/// scalar permutation.
pub const VECTORIZED: bool = cfg!(any(
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon"),
));

/// Run sixteen permutations, one a lane. Words must lie in `[0, P]`; the
/// outputs are canonical.
pub fn permute_x16(state: &mut States) {
    debug_assert!(state.iter().flatten().all(|&word| word <= P));
    #[cfg(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon"),
    ))]
    {
        let mut vectors: [V16; N_STATE] = core::array::from_fn(|i| V16::load(&state[i]));
        permute_vectors(&mut vectors);
        for (word, vector) in state.iter_mut().zip(vectors) {
            *word = vector.canonical().store();
        }
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon"),
    )))]
    permute_x16_scalar(state);
}

/// The reference permutation on each lane in turn.
#[cfg_attr(
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon"),
    ),
    allow(dead_code)
)]
pub(crate) fn permute_x16_scalar(state: &mut States) {
    for lane in 0..LANES {
        let mut words: [M31; N_STATE] = core::array::from_fn(|i| M31::from(state[i][lane]));
        crate::permute(&mut words);
        for (word, value) in state.iter_mut().zip(words) {
            word[lane] = value.value();
        }
    }
}

/// Sixteen lanes of M31 words in `[0, P]`, in one instruction set's registers.
///
/// Every operation takes and returns words in `[0, P]` unless it says
/// otherwise; `P` stands for zero until [`Vector::canonical`].
pub(crate) trait Vector: Copy {
    fn load(words: &[u32; LANES]) -> Self;
    fn store(self) -> [u32; LANES];
    /// `self + rhs` mod P.
    fn add(self, rhs: Self) -> Self;
    /// `self - rhs` mod P.
    fn sub(self, rhs: Self) -> Self;
    /// `(self + constant)^5` mod P, for a canonical round constant.
    fn add_constant_and_sbox(self, constant: u32) -> Self;
    /// `self · 2^I` mod P, a rotation of the 31-bit word; `I + I_PRIME = 31`.
    fn mul_2exp<const I: i32, const I_PRIME: i32>(self) -> Self;
    /// `self · 2^15` mod P.
    fn mul_2exp_15(self) -> Self {
        self.mul_2exp::<15, 16>()
    }
    /// The canonical form: `P` becomes 0.
    fn canonical(self) -> Self;

    fn double(self) -> Self {
        self.add(self)
    }
}

/// The reference Poseidon2 arrangement on sixteen lanes: the external
/// matrix, 4 full rounds, 14 partial rounds, 4 full rounds (as
/// [`crate::permute_with`] under the reference constants).
#[inline(always)]
pub(crate) fn permute_vectors<V: Vector>(state: &mut [V; N_STATE]) {
    external_matrix(state);
    for constants in &EXTERNAL_ROUND_CONSTS[..N_HALF_FULL_ROUNDS] {
        full_round(state, constants);
    }
    for constant in &INTERNAL_ROUND_CONSTS[..N_PARTIAL_ROUNDS] {
        partial_round(state, constant.value());
    }
    for constants in &EXTERNAL_ROUND_CONSTS[N_HALF_FULL_ROUNDS..FULL_ROUNDS] {
        full_round(state, constants);
    }
}

#[inline(always)]
fn full_round<V: Vector>(state: &mut [V; N_STATE], constants: &[M31; N_STATE]) {
    for (word, constant) in state.iter_mut().zip(constants) {
        *word = word.add_constant_and_sbox(constant.value());
    }
    external_matrix(state);
}

/// The S-box on word 0, then `1 + diag(V)` with `V = [-2, 2^0, 2^1, …]`:
/// word 0 becomes `sum - 2·s0 = sum_tail - s0`, every other word
/// `sum + V_i·s_i`.
#[inline(always)]
fn partial_round<V: Vector>(state: &mut [V; N_STATE], constant: u32) {
    state[0] = state[0].add_constant_and_sbox(constant);
    let sum_tail = sum_15(state);
    let sum = sum_tail.add(state[0]);
    state[0] = sum_tail.sub(state[0]);
    diagonal_mul(state);
    for word in &mut state[1..] {
        *word = word.add(sum);
    }
}

/// `state[1..]` times `2^INTERNAL_DIAG_SHIFTS`: the shifts 0, 1, 2, …, 8, 10,
/// 12, 13, 14, 15, 16.
#[inline(always)]
fn diagonal_mul<V: Vector>(state: &mut [V; N_STATE]) {
    const {
        assert!(matches!(
            INTERNAL_DIAG_SHIFTS,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16]
        ));
    }
    state[2] = state[2].double();
    state[3] = state[3].mul_2exp::<2, 29>();
    state[4] = state[4].mul_2exp::<3, 28>();
    state[5] = state[5].mul_2exp::<4, 27>();
    state[6] = state[6].mul_2exp::<5, 26>();
    state[7] = state[7].mul_2exp::<6, 25>();
    state[8] = state[8].mul_2exp::<7, 24>();
    state[9] = state[9].mul_2exp::<8, 23>();
    state[10] = state[10].mul_2exp::<10, 21>();
    state[11] = state[11].mul_2exp::<12, 19>();
    state[12] = state[12].mul_2exp::<13, 18>();
    state[13] = state[13].mul_2exp::<14, 17>();
    state[14] = state[14].mul_2exp_15();
    state[15] = state[15].mul_2exp::<16, 15>();
}

#[inline(always)]
fn sum_15<V: Vector>(state: &[V; N_STATE]) -> V {
    let s = |a: usize, b: usize| state[a].add(state[b]);
    let quad = |a: usize| s(a, a + 1).add(s(a + 2, a + 3));
    let eight = quad(1).add(quad(5));
    let seven = quad(9).add(s(13, 14).add(state[15]));
    eight.add(seven)
}

/// `circ(2·M4, M4, M4, M4)`, as [`crate::apply_external_round_matrix`].
#[inline(always)]
fn external_matrix<V: Vector>(state: &mut [V; N_STATE]) {
    for block in state.chunks_exact_mut(4) {
        let [x0, x1, x2, x3] = [block[0], block[1], block[2], block[3]];
        let t01 = x0.add(x1);
        let t23 = x2.add(x3);
        let t0123 = t01.add(t23);
        let t01123 = t0123.add(x1);
        let t01233 = t0123.add(x3);
        block[0] = t01123.add(t01);
        block[1] = t01123.add(x2.double());
        block[2] = t01233.add(t23);
        block[3] = t01233.add(x0.double());
    }
    let sums: [V; 4] = core::array::from_fn(|k| {
        state[k]
            .add(state[k + 4])
            .add(state[k + 8].add(state[k + 12]))
    });
    for (i, word) in state.iter_mut().enumerate() {
        *word = word.add(sums[i % 4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stream of words in `[0, P]`, P included.
    fn words(seed: u64) -> impl Iterator<Item = u32> {
        let mut x = seed;
        core::iter::from_fn(move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            Some(match x % 64 {
                0 => 0,
                1 => P,
                2 => P - 1,
                _ => (x >> 33) as u32 % (P + 1),
            })
        })
    }

    fn reference(state: &States, lane: usize) -> [u32; N_STATE] {
        let mut words: [M31; N_STATE] = core::array::from_fn(|i| M31::from(state[i][lane]));
        crate::permute(&mut words);
        words.map(M31::value)
    }

    #[test]
    fn sixteen_lanes_equal_the_reference_permutation() {
        let mut stream = words(0x9e37_79b9_7f4a_7c15);
        for _ in 0..64 {
            let input: States =
                core::array::from_fn(|_| core::array::from_fn(|_| stream.next().unwrap()));
            let mut output = input;
            permute_x16(&mut output);
            for lane in 0..LANES {
                let expected = reference(&input, lane);
                let got: [u32; N_STATE] = core::array::from_fn(|i| output[i][lane]);
                assert_eq!(got, expected, "lane {lane}");
            }
        }
    }

    #[test]
    fn the_scalar_fallback_equals_the_reference_permutation() {
        let mut stream = words(7);
        let input: States =
            core::array::from_fn(|_| core::array::from_fn(|_| stream.next().unwrap()));
        let mut output = input;
        permute_x16_scalar(&mut output);
        for lane in 0..LANES {
            let got: [u32; N_STATE] = core::array::from_fn(|i| output[i][lane]);
            assert_eq!(got, reference(&input, lane));
        }
    }
}
