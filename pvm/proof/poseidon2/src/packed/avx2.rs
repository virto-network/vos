//! AVX2: sixteen lanes as two 256-bit registers a word.
//!
//! Adapted from Plonky3 at revision `f98331687e47106a64ab82a77e2e1d0d66c9161b`,
//! <https://github.com/Plonky3/Plonky3>: `mersenne-31/src/x86_64_avx2/packing.rs`
//! (`exp5` and its helpers), `mersenne-31/src/x86_64_avx2/utils.rs`
//! (`add_rc_and_sbox`, the negative form of round constants),
//! `mersenne-31/src/x86_64_avx2/poseidon2.rs` (`mul_2exp_i`, `mul_2exp_15`) and
//! `field/src/packed/x86_64_avx.rs` (`mm256_mod_add`, `mm256_mod_sub`).
//! Copyright (c) 2022 The Plonky3 Authors, licensed MIT or Apache-2.0
//! (`LICENSE-PLONKY3-MIT`). Changed here: the functions act on a pair of
//! registers holding sixteen lanes, and a round constant is negated when it is
//! broadcast rather than when a permutation is built.

use core::arch::x86_64::{self as x86, __m256i};
use core::mem::transmute;

use super::{LANES, Vector};

const P: __m256i = unsafe { transmute::<[u32; 8], __m256i>([super::P; 8]) };

/// Sixteen lanes: lanes 0..8 in the first register, 8..16 in the second.
#[derive(Clone, Copy)]
pub(super) struct V16([__m256i; 2]);

impl V16 {
    #[inline(always)]
    fn map(self, f: impl Fn(__m256i) -> __m256i) -> Self {
        Self([f(self.0[0]), f(self.0[1])])
    }

    #[inline(always)]
    fn zip(self, rhs: Self, f: impl Fn(__m256i, __m256i) -> __m256i) -> Self {
        Self([f(self.0[0], rhs.0[0]), f(self.0[1], rhs.0[1])])
    }
}

impl Vector for V16 {
    #[inline(always)]
    fn load(words: &[u32; LANES]) -> Self {
        // SAFETY: `words` holds 64 readable bytes; the loads are unaligned.
        unsafe {
            let ptr = words.as_ptr().cast::<__m256i>();
            Self([
                x86::_mm256_loadu_si256(ptr),
                x86::_mm256_loadu_si256(ptr.add(1)),
            ])
        }
    }

    #[inline(always)]
    fn store(self) -> [u32; LANES] {
        // SAFETY: two 256-bit registers are 16 `u32`s, in lane order.
        unsafe { transmute::<[__m256i; 2], [u32; LANES]>(self.0) }
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        self.zip(rhs, mod_add)
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.zip(rhs, mod_sub)
    }

    #[inline(always)]
    fn add_constant_and_sbox(self, constant: u32) -> Self {
        // SAFETY: the module is compiled only for targets with AVX2.
        unsafe {
            // The constant in negative form, `constant - P` in [-P, 0], so that the
            // sum lies in [-P, P], the range `exp5` takes.
            let constant = x86::_mm256_set1_epi32(constant as i32 - super::P as i32);
            self.map(|x| exp5(x86::_mm256_add_epi32(x, constant)))
        }
    }

    #[inline(always)]
    fn mul_2exp<const I: i32, const I_PRIME: i32>(self) -> Self {
        self.map(mul_2exp_i::<I, I_PRIME>)
    }

    #[inline(always)]
    fn mul_2exp_15(self) -> Self {
        self.map(mul_2exp_15)
    }

    #[inline(always)]
    fn canonical(self) -> Self {
        // SAFETY: the module is compiled only for targets with AVX2.
        unsafe {
            // [0, P] → [0, P): P - P = 0 is the smaller; below P, x - P wraps.
            self.map(|x| x86::_mm256_min_epu32(x, x86::_mm256_sub_epi32(x, P)))
        }
    }
}

/// `(lhs + rhs) mod P` for words in [0, P]; the result is in [0, P].
#[inline(always)]
fn mod_add(lhs: __m256i, rhs: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        //      vpaddd   t, lhs, rhs
        //      vpsubd   u, t, P
        //      vpminud  res, t, u
        let t = x86::_mm256_add_epi32(lhs, rhs);
        let u = x86::_mm256_sub_epi32(t, P);
        x86::_mm256_min_epu32(t, u)
    }
}

/// `(lhs - rhs) mod P` for words in [0, P]; the result is in [0, P].
#[inline(always)]
fn mod_sub(lhs: __m256i, rhs: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        //      vpsubd   t, lhs, rhs
        //      vpaddd   u, t, P
        //      vpminud  res, t, u
        let t = x86::_mm256_sub_epi32(lhs, rhs);
        let u = x86::_mm256_add_epi32(t, P);
        x86::_mm256_min_epu32(t, u)
    }
}

/// `x · 2^I` mod P for `x` in [0, P]: a rotation of the 31-bit word.
#[inline(always)]
fn mul_2exp_i<const I: i32, const I_PRIME: i32>(x: __m256i) -> __m256i {
    const {
        assert!(I + I_PRIME == 31);
    }
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        //      vpslld   hi_dirty, x,        I
        //      vpsrld   lo,       x,        31 - I
        //      vpand    hi,       hi_dirty, P
        //      vpor     res,      lo,       hi
        let hi_bits_dirty = x86::_mm256_slli_epi32::<I>(x);
        let lo_bits = x86::_mm256_srli_epi32::<I_PRIME>(x);
        let hi_bits = x86::_mm256_and_si256(hi_bits_dirty, P);
        x86::_mm256_or_si256(lo_bits, hi_bits)
    }
}

/// `x · 2^15` mod P for `x` in [0, P], through `vpmaddwd`.
///
/// With `x = x_lo + 2^16 x_hi`, the target is `y = x_hi + 2^15 x_lo < 2^31`.
/// `vpmaddwd` with `C = [-2^15, -1]` a lane, reading `x_lo` as signed, gives
/// `-x_hi - 2^15 (x_lo - 2^16 x_16) = -y + 2^31 x_16`. Adding P gives
/// `2^31 (1 + x_16) + (NOT y)` mod 2^32, and clearing the sign bit of its
/// complement leaves `y`.
#[inline(always)]
fn mul_2exp_15(x: __m256i) -> __m256i {
    //      vpmaddwd  neg_madds,     x,             C
    //      vpaddd    dirty_neg_res, neg_madds,     P
    //      vpandn    res,           dirty_neg_res, P
    const C: __m256i =
        unsafe { transmute::<[[i16; 2]; 8], __m256i>([[(-1_i16) << 15, -1_i16]; 8]) };
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        let neg_madds = x86::_mm256_madd_epi16(x, C);
        let dirty_neg_output = x86::_mm256_add_epi32(neg_madds, P);
        x86::_mm256_andnot_si256(dirty_neg_output, P)
    }
}

#[inline(always)]
fn movehdup_epi32(x: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        // The instruction exists only in the floating-point flavour.
        x86::_mm256_castps_si256(x86::_mm256_movehdup_ps(x86::_mm256_castsi256_ps(x)))
    }
}

#[inline(always)]
fn moveldup_epi32(x: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        // The instruction exists only in the floating-point flavour.
        x86::_mm256_castps_si256(x86::_mm256_moveldup_ps(x86::_mm256_castsi256_ps(x)))
    }
}

/// Reduce a representative in {0, ..., P^2} to a representative in [-P, P].
/// If the input is greater than P^2, the output still corresponds to the same
/// class but lies in [-P, 2^34].
#[inline(always)]
fn partial_reduce_neg(x: __m256i) -> __m256i {
    const LOW31: __m256i = unsafe { transmute::<[u64; 4], __m256i>([0x7fff_ffff; 4]) };
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        // Get the top bits shifted down.
        let hi = x86::_mm256_srli_epi64::<31>(x);
        // nand instead of and means this returns P - lo.
        let neg_lo = x86::_mm256_andnot_si256(x, LOW31);
        x86::_mm256_sub_epi64(hi, neg_lo)
    }
}

/// The square of the field elements in the even 32-bit indices, represented
/// as values in {-P, ..., P}; values in the odd indices are ignored.
#[inline(always)]
fn square_unred(x: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        let x2 = x86::_mm256_mul_epi32(x, x);
        partial_reduce_neg(x2)
    }
}

/// `x -> x^5` on field elements represented as signed values in
/// {-P, ..., P}, producing output in {0, ..., P}. Round constants are added in
/// their negative form so that a word plus its constant lies in this range.
#[inline(always)]
fn exp5(x: __m256i) -> __m256i {
    // SAFETY: the module is compiled only for targets with AVX2.
    unsafe {
        let input_evn = x;
        let input_odd = movehdup_epi32(x);

        let evn_sq = square_unred(input_evn);
        let odd_sq = square_unred(input_odd);

        let evn_4 = square_unred(evn_sq);
        let odd_4 = square_unred(odd_sq);

        let evn_5 = x86::_mm256_mul_epi32(evn_4, input_evn);
        let odd_5 = x86::_mm256_mul_epi32(odd_4, input_odd);

        // Marked dirty as the top bit needs to be cleared.
        let odd_5_lo_dirty = moveldup_epi32(odd_5);
        let odd_5_hi = x86::_mm256_add_epi64(odd_5, odd_5);
        let evn_5_hi = x86::_mm256_srli_epi64::<31>(evn_5);

        // Marked dirty as the top bit needs to be cleared.
        let lo_dirty = x86::_mm256_blend_epi32::<0b1010_1010>(evn_5, odd_5_lo_dirty);
        let hi = x86::_mm256_blend_epi32::<0b1010_1010>(evn_5_hi, odd_5_hi);
        let lo = x86::_mm256_and_si256(lo_dirty, P);
        let corr = x86::_mm256_sign_epi32(P, hi);
        let t = x86::_mm256_add_epi32(hi, lo);
        let u = x86::_mm256_sub_epi32(t, corr);
        x86::_mm256_min_epu32(t, u)
    }
}
