//! NEON: sixteen lanes as four 128-bit registers a word.
//!
//! Adapted from Plonky3 at revision `f98331687e47106a64ab82a77e2e1d0d66c9161b`,
//! <https://github.com/Plonky3/Plonky3>: `mersenne-31/src/aarch64_neon/packing.rs`
//! (`mul`, `mul_31x31_to_hi_31`, `reduce_sum`, `exp5`),
//! `mersenne-31/src/aarch64_neon/utils.rs` (`add_rc_and_sbox`),
//! `mersenne-31/src/aarch64_neon/poseidon2.rs` (`mul_2exp_i`) and
//! `field/src/packed/aarch64_neon.rs` (`uint32x4_mod_add`, `uint32x4_mod_sub`).
//! Copyright (c) 2022 The Plonky3 Authors, licensed MIT or Apache-2.0
//! (`LICENSE-PLONKY3-MIT`). Changed here: the functions act on four registers
//! holding sixteen lanes.

use core::arch::aarch64::{self as neon, uint32x4_t};
use core::mem::transmute;

use super::{LANES, Vector};

const P: uint32x4_t = unsafe { transmute::<[u32; 4], uint32x4_t>([super::P; 4]) };

/// Sixteen lanes: lanes `4r..4r + 4` in register `r`.
#[derive(Clone, Copy)]
pub(super) struct V16([uint32x4_t; 4]);

impl V16 {
    #[inline(always)]
    fn map(self, f: impl Fn(uint32x4_t) -> uint32x4_t) -> Self {
        Self(self.0.map(f))
    }

    #[inline(always)]
    fn zip(self, rhs: Self, f: impl Fn(uint32x4_t, uint32x4_t) -> uint32x4_t) -> Self {
        Self(core::array::from_fn(|r| f(self.0[r], rhs.0[r])))
    }
}

impl Vector for V16 {
    #[inline(always)]
    fn load(words: &[u32; LANES]) -> Self {
        // SAFETY: `words` holds 16 readable `u32`s; `vld1q_u32` needs only
        // element alignment.
        Self(core::array::from_fn(|r| unsafe {
            neon::vld1q_u32(words.as_ptr().add(4 * r))
        }))
    }

    #[inline(always)]
    fn store(self) -> [u32; LANES] {
        // SAFETY: four 128-bit registers are 16 `u32`s, in lane order.
        unsafe { transmute::<[uint32x4_t; 4], [u32; LANES]>(self.0) }
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        // SAFETY: the module is compiled only for targets with NEON.
        unsafe { self.zip(rhs, |a, b| reduce_sum(neon::vaddq_u32(a, b))) }
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        // SAFETY: the module is compiled only for targets with NEON.
        unsafe {
            self.zip(rhs, |a, b| {
                let t = neon::vsubq_u32(a, b);
                let u = neon::vaddq_u32(t, P);
                neon::vminq_u32(t, u)
            })
        }
    }

    #[inline(always)]
    fn add_constant_and_sbox(self, constant: u32) -> Self {
        // SAFETY: the module is compiled only for targets with NEON.
        unsafe {
            // The sum is in [0, 2P]; reduced to [0, P] it is the input `exp5`
            // takes.
            let constant = neon::vdupq_n_u32(constant);
            self.map(|x| exp5(reduce_sum(neon::vaddq_u32(x, constant))))
        }
    }

    #[inline(always)]
    fn mul_2exp<const I: i32, const I_PRIME: i32>(self) -> Self {
        const {
            assert!(I + I_PRIME == 31);
        }
        // SAFETY: the module is compiled only for targets with NEON.
        unsafe {
            self.map(|x| {
                // The high bits down, then the low bits shifted up and inserted
                // above them; clear the sign bit.
                let lo = neon::vshrq_n_u32::<I_PRIME>(x);
                let inserted = neon::vsliq_n_u32::<I>(lo, x);
                neon::vandq_u32(inserted, P)
            })
        }
    }

    #[inline(always)]
    fn canonical(self) -> Self {
        // SAFETY: the module is compiled only for targets with NEON.
        unsafe {
            // [0, P] → [0, P): P - P = 0 is the smaller; below P, x - P wraps.
            self.map(|x| neon::vminq_u32(x, neon::vsubq_u32(x, P)))
        }
    }
}

/// Given a `val` in `0, ..., 2 P`, return a `res` in `0, ..., P` such that
/// `res = val (mod P)`.
#[inline(always)]
fn reduce_sum(val: uint32x4_t) -> uint32x4_t {
    // SAFETY: the module is compiled only for targets with NEON.
    unsafe {
        // val is in 0, ..., 2 P. If val is in 0, ..., P - 1 then it is valid and
        // u := (val - P) mod 2^32 is in P <u 2^32 - P, ..., 2^32 - 1 and
        // unsigned_min(val, u) = val as desired. If val is in P + 1, ..., 2 P,
        // then u is in 1, ..., P < P + 1 so u is valid, and unsigned_min(val, u)
        // = u as desired. The remaining case of val = P, u = 0 is trivial.
        let u = neon::vsubq_u32(val, P);
        neon::vminq_u32(val, u)
    }
}

/// Multiply two 31-bit numbers to obtain a 62-bit immediate result, and
/// return the high 31 bits of that result.
#[inline(always)]
fn mul_31x31_to_hi_31(lhs: uint32x4_t, rhs: uint32x4_t) -> uint32x4_t {
    // SAFETY: the module is compiled only for targets with NEON.
    unsafe {
        neon::vreinterpretq_u32_s32(neon::vqdmulhq_s32(
            neon::vreinterpretq_s32_u32(lhs),
            neon::vreinterpretq_s32_u32(rhs),
        ))
    }
}

/// Multiply field elements that fit in 31 bits; the result is in [0, P].
#[inline(always)]
fn mul(lhs: uint32x4_t, rhs: uint32x4_t) -> uint32x4_t {
    // SAFETY: the module is compiled only for targets with NEON.
    unsafe {
        //      sqdmulh  prod_hi31.4s, lhs.4s, rhs.4s
        //      mul      t.4s, lhs.4s, rhs.4s
        //      mla      t.4s, prod_hi31.4s, P.4s
        //      sub      u.4s, t.4s, P.4s
        //      umin     res.4s, t.4s, u.4s
        //
        // Let prod := lhs * rhs = 2^31 prod_hi31 + prod_lo31, both limbs in
        // 0, ..., 2^31 - 1. Then prod = prod_hi31 + prod_lo31 (mod P) =: t, and
        //   t = prod_lo32 - 2^31 prod_hi31 + prod_hi31 = prod_lo32 - prod_hi31 * P
        // (mod 2^32), with t in 0, ..., 2 P.
        let prod_hi31 = mul_31x31_to_hi_31(lhs, rhs);
        let prod_lo32 = neon::vmulq_u32(lhs, rhs);
        let t = neon::vmlsq_u32(prod_lo32, prod_hi31, P);
        reduce_sum(t)
    }
}

/// `x -> x^5` for `x` in [0, P]; the result is in [0, P].
#[inline(always)]
fn exp5(x: uint32x4_t) -> uint32x4_t {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    mul(x4, x)
}
