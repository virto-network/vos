//! AVX-512F: sixteen lanes in one 512-bit register a word.
//!
//! Adapted from Plonky3 at revision `f98331687e47106a64ab82a77e2e1d0d66c9161b`,
//! <https://github.com/Plonky3/Plonky3>: `mersenne-31/src/x86_64_avx512/packing.rs`
//! (`exp5` and its helpers), `mersenne-31/src/x86_64_avx512/utils.rs`
//! (`add_rc_and_sbox`, the negative form of round constants),
//! `mersenne-31/src/x86_64_avx512/poseidon2.rs` (`mul_2exp_i`) and
//! `field/src/packed/x86_64_avx.rs` (`mm512_mod_add`, `mm512_mod_sub`).
//! Copyright (c) 2022 The Plonky3 Authors, licensed MIT or Apache-2.0
//! (`LICENSE-PLONKY3-MIT`). Changed here: a round constant is negated when it
//! is broadcast rather than when a permutation is built, `mul_2exp_i` shifts
//! by a count register (a constant count compiles to the immediate form), and
//! `exp5` reads the sign bits with `vpcmpd` (AVX-512F) instead of `vpmovd2m`
//! (AVX-512DQ).

use core::arch::x86_64::{self as x86, __m512i, __mmask16};
use core::mem::transmute;

use super::{LANES, Vector};

const P: __m512i = unsafe { transmute::<[u32; LANES], __m512i>([super::P; LANES]) };
const ODDS: __mmask16 = 0b1010_1010_1010_1010;

/// Sixteen lanes, lane `l` in 32-bit element `l`.
#[derive(Clone, Copy)]
pub(super) struct V16(__m512i);

impl Vector for V16 {
    #[inline(always)]
    fn load(words: &[u32; LANES]) -> Self {
        // SAFETY: `words` holds 64 readable bytes; the load is unaligned.
        Self(unsafe { x86::_mm512_loadu_si512(words.as_ptr().cast()) })
    }

    #[inline(always)]
    fn store(self) -> [u32; LANES] {
        // SAFETY: a 512-bit register is 16 `u32`s, in lane order.
        unsafe { transmute::<__m512i, [u32; LANES]>(self.0) }
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        // SAFETY: the module is compiled only for targets with AVX-512F.
        unsafe {
            //      vpaddd   t, lhs, rhs
            //      vpsubd   u, t, P
            //      vpminud  res, t, u
            let t = x86::_mm512_add_epi32(self.0, rhs.0);
            let u = x86::_mm512_sub_epi32(t, P);
            Self(x86::_mm512_min_epu32(t, u))
        }
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        // SAFETY: the module is compiled only for targets with AVX-512F.
        unsafe {
            //      vpsubd   t, lhs, rhs
            //      vpaddd   u, t, P
            //      vpminud  res, t, u
            let t = x86::_mm512_sub_epi32(self.0, rhs.0);
            let u = x86::_mm512_add_epi32(t, P);
            Self(x86::_mm512_min_epu32(t, u))
        }
    }

    #[inline(always)]
    fn add_constant_and_sbox(self, constant: u32) -> Self {
        // SAFETY: the module is compiled only for targets with AVX-512F.
        unsafe {
            // The constant in negative form, `constant - P` in [-P, 0], so that the
            // sum lies in [-P, P], the range `exp5` takes.
            let constant = x86::_mm512_set1_epi32(constant as i32 - super::P as i32);
            Self(exp5(x86::_mm512_add_epi32(self.0, constant)))
        }
    }

    #[inline(always)]
    fn mul_2exp<const I: i32, const I_PRIME: i32>(self) -> Self {
        const {
            assert!(I + I_PRIME == 31);
        }
        // SAFETY: the module is compiled only for targets with AVX-512F.
        unsafe {
            // Shift the low bits up; this also shifts something unwanted into the
            // sign bit, so it is dirty.
            // (A constant count compiles to the immediate form.)
            let hi_bits_dirty = x86::_mm512_sll_epi32(self.0, x86::_mm_cvtsi32_si128(I));
            // Shift the high bits down.
            let lo_bits = x86::_mm512_srl_epi32(self.0, x86::_mm_cvtsi32_si128(I_PRIME));
            // lo OR (hi_dirty AND P), with bit pattern 111 => 1, 110 => 1,
            // 101 => 1, 100 => 1, 011 => 1, 010 => 0, 001 => 0, 000 => 0. The
            // patterns 111, 110 and 100 cannot occur, so any constant of the form
            // **1*1000 works.
            Self(x86::_mm512_ternarylogic_epi32::<0b1111_1000>(
                lo_bits,
                hi_bits_dirty,
                P,
            ))
        }
    }

    #[inline(always)]
    fn canonical(self) -> Self {
        // SAFETY: the module is compiled only for targets with AVX-512F.
        unsafe {
            // [0, P] → [0, P): P - P = 0 is the smaller; below P, x - P wraps.
            Self(x86::_mm512_min_epu32(
                self.0,
                x86::_mm512_sub_epi32(self.0, P),
            ))
        }
    }
}

#[inline(always)]
fn movehdup_epi32(a: __m512i) -> __m512i {
    // SAFETY: the module is compiled only for targets with AVX-512F.
    unsafe {
        // The instruction exists only in the floating-point flavour.
        x86::_mm512_castps_si512(x86::_mm512_movehdup_ps(x86::_mm512_castsi512_ps(a)))
    }
}

#[inline(always)]
fn mask_moveldup_epi32(src: __m512i, k: __mmask16, a: __m512i) -> __m512i {
    // SAFETY: the module is compiled only for targets with AVX-512F.
    unsafe {
        // The instruction exists only in the floating-point flavour.
        let src = x86::_mm512_castsi512_ps(src);
        let a = x86::_mm512_castsi512_ps(a);
        x86::_mm512_castps_si512(x86::_mm512_mask_moveldup_ps(src, k, a))
    }
}

/// Reduce a representative in {0, ..., P^2} to a representative in [-P, P].
/// If the input is greater than P^2, the output still corresponds to the same
/// class but lies in [-P, 2^34].
#[inline(always)]
fn partial_reduce_neg(x: __m512i) -> __m512i {
    const LOW31: __m512i = unsafe { transmute::<[u64; 8], __m512i>([0x7fff_ffff; 8]) };
    // SAFETY: the module is compiled only for targets with AVX-512F.
    unsafe {
        // Get the top bits shifted down.
        let hi = x86::_mm512_srli_epi64::<31>(x);
        // nand instead of and means this returns P - lo.
        let neg_lo = x86::_mm512_andnot_si512(x, LOW31);
        x86::_mm512_sub_epi64(hi, neg_lo)
    }
}

/// The square of the field elements in the even 32-bit indices, represented
/// as values in {-P, ..., P}; the top half of each 64-bit lane is ignored.
#[inline(always)]
fn square_unred(x: __m512i) -> __m512i {
    // SAFETY: the module is compiled only for targets with AVX-512F.
    unsafe {
        let x2 = x86::_mm512_mul_epi32(x, x);
        partial_reduce_neg(x2)
    }
}

/// `x -> x^5` on field elements represented as signed values in
/// {-P, ..., P}, producing output in {0, ..., P}. Round constants are added in
/// their negative form so that a word plus its constant lies in this range.
#[inline(always)]
fn exp5(x: __m512i) -> __m512i {
    // SAFETY: the module is compiled only for targets with AVX-512F.
    unsafe {
        let input_evn = x;
        let input_odd = movehdup_epi32(x);

        let evn_sq = square_unred(input_evn);
        let odd_sq = square_unred(input_odd);

        let evn_4 = square_unred(evn_sq);
        let odd_4 = square_unred(odd_sq);

        let evn_5 = x86::_mm512_mul_epi32(evn_4, input_evn);
        let odd_5 = x86::_mm512_mul_epi32(odd_4, input_odd);

        // Marked dirty as the top bit needs to be cleared.
        let lo_dirty = mask_moveldup_epi32(evn_5, ODDS, odd_5);

        let odd_5_hi = x86::_mm512_add_epi64(odd_5, odd_5);
        let evn_5_hi = x86::_mm512_srli_epi64::<31>(evn_5);
        let hi = x86::_mm512_mask_blend_epi32(ODDS, evn_5_hi, odd_5_hi);

        let zero = x86::_mm512_setzero_si512();
        let signs = x86::_mm512_cmplt_epi32_mask(hi, zero);
        let corr = x86::_mm512_mask_sub_epi32(P, signs, zero, P);

        let lo = x86::_mm512_and_si512(lo_dirty, P);

        let t = x86::_mm512_add_epi32(hi, lo);
        let u = x86::_mm512_sub_epi32(t, corr);
        x86::_mm512_min_epu32(t, u)
    }
}
