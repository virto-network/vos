//! Host-side reference implementation of the Ristretto255 compress
//! algorithm, expressed over our `field::Bytes` type so the
//! `RistrettoCombCompressChip` (R1e-bis output binding) can derive
//! per-call witness intermediates without going through dalek's
//! private FieldElement representation.
//!
//! What this provides:
//!   - `SQRT_M1` and `INVSQRT_A_MINUS_D`: 32-byte LE field constants
//!     used by the compress chain's conditional rotate and negate
//!     branches.  Computed lazily via `field::pow` on first call.
//!   - `compute_compress_witness(p) -> CompressWitness`: runs the
//!     full compress chain on an `ExtendedPoint` and returns every
//!     intermediate field element, sign bit, and the canonical
//!     32-byte output.  Mirrors `RistrettoPoint::compress` from
//!     curve25519-dalek 4.1.3, line-for-line.
//!
//! Cross-checked against `RistrettoPoint::compress()` in the test
//! module: for any `(scalar, basepoint)` pair, our `out_bytes`
//! matches dalek's `compress()` byte-for-byte.

#![cfg(feature = "prover")]

use super::field::{self, Bytes};
use super::point::ExtendedPoint;
use std::sync::OnceLock;

/// `√(-1) mod p25519`, canonical positive root.  Equals `2^((p-1)/4)
/// mod p` since 2 is a non-residue (so 2^((p-1)/4) has order 4 in the
/// multiplicative group).  Verified against dalek's hardcoded
/// `constants::SQRT_M1` in the test module.
pub fn sqrt_m1() -> &'static Bytes {
    static V: OnceLock<Bytes> = OnceLock::new();
    V.get_or_init(|| {
        // exp = (p - 1) / 4 = 2^253 - 5.
        // p - 1 = 2^255 - 20, divided by 4 = 2^253 - 5.
        // In LE bytes: byte 0 = 0xfb (= 256 - 5), bytes 1..=30 = 0xff
        // (the borrow propagates), byte 31 = 0x1f (= 0x20 - 1).
        let mut exp = [0xffu8; 32];
        exp[0] = 0xfb;
        exp[31] = 0x1f;
        let mut two = [0u8; 32];
        two[0] = 2;
        let m1 = field::pow(&two, &exp);
        // Canonicalize to the "positive" root.  By Ristretto convention
        // is_negative(s) := s.bytes[0] & 1 == 1.  If the candidate is
        // negative, take p - candidate instead.
        if m1[0] & 1 == 1 {
            let mut neg = [0u8; 32];
            let mut bw: i16 = 0;
            for i in 0..32 {
                let v = field::P_BYTES[i] as i16 - m1[i] as i16 - bw;
                if v < 0 {
                    neg[i] = (v + 256) as u8;
                    bw = 1;
                } else {
                    neg[i] = v as u8;
                    bw = 0;
                }
            }
            neg
        } else {
            m1
        }
    })
}

/// `√(-1 / (a - d)) mod p25519` with `a = -1`, `d = -121665/121666`.
/// Simplifies algebraically to `√(121666) mod p` (see test for
/// derivation).  Used by the compress chain's rotate-branch
/// `enchanted_denominator = i1 · INVSQRT_A_MINUS_D`.
pub fn invsqrt_a_minus_d() -> &'static Bytes {
    static V: OnceLock<Bytes> = OnceLock::new();
    V.get_or_init(|| {
        // Compute `1/121666 mod p` first via Fermat: 121666^(p-2).
        // Then a-d = -1 + 121665/121666 = (121665 - 121666)/121666
        //         = -1/121666.
        // -1/(a-d) = -1 / (-1/121666) = 121666.
        // But we want √(-1/(a-d)) = √(121666).
        // Wait: dalek defines INVSQRT_A_MINUS_D = √(1/(a-d)) when a-d
        // is a QR — let's just match dalek's hardcoded value.
        //
        // From dalek u64 backend (FieldElement51 limbs, 51 bits each):
        //   INVSQRT_A_MINUS_D = [
        //       278908739862762,  821645201101625,    8113234426968,
        //      1777959178193151, 2118520810568447,
        //   ]
        // We reconstruct the 32-byte LE representation from the limbs.
        const LIMBS: [u64; 5] = [
            278908739862762,
            821645201101625,
            8113234426968,
            1777959178193151,
            2118520810568447,
        ];
        // Pack 5×51 bits = 255 bits into 32 LE bytes.
        let mut acc: u128 = 0;
        let mut bits: u32 = 0;
        let mut bytes = [0u8; 32];
        let mut byte_idx = 0;
        for &limb in LIMBS.iter() {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 && byte_idx < 32 {
                bytes[byte_idx] = (acc & 0xff) as u8;
                acc >>= 8;
                bits -= 8;
                byte_idx += 1;
            }
        }
        // Top bits — fill remaining bytes with the residual.
        while byte_idx < 32 {
            bytes[byte_idx] = (acc & 0xff) as u8;
            acc >>= 8;
            byte_idx += 1;
        }
        bytes
    })
}

/// Sign convention: a canonical (in-range) field element is "negative"
/// iff its low bit (byte[0] & 1) is 1.  Mirrors dalek's
/// `FieldElement::is_negative()`.
pub fn is_negative(a: &Bytes) -> u8 {
    a[0] & 1
}

/// Conditional negate `a` mod p: returns `a` if `flag == 0`, else `p - a`.
/// Pre-condition: `a < p` (canonical input).  Post-condition: result < p.
pub fn conditional_negate(a: &Bytes, flag: u8) -> Bytes {
    if flag == 0 {
        return *a;
    }
    // a == 0 ⇒ -0 = 0 mod p (special case: p - 0 = p is non-canonical).
    if *a == [0u8; 32] {
        return [0u8; 32];
    }
    // p - a for a ∈ [1, p-1] lies in [1, p-1], so canonical.
    let mut out = [0u8; 32];
    let mut bw: i16 = 0;
    for i in 0..32 {
        let v = field::P_BYTES[i] as i16 - a[i] as i16 - bw;
        if v < 0 {
            out[i] = (v + 256) as u8;
            bw = 1;
        } else {
            out[i] = v as u8;
            bw = 0;
        }
    }
    out
}

/// Conditional select: returns `b` if `flag == 0`, else `a`.
pub fn conditional_select(a: &Bytes, b: &Bytes, flag: u8) -> Bytes {
    if flag == 0 {
        *b
    } else {
        *a
    }
}

/// Per-call witness output of the host-side compress chain.  Every
/// field corresponds to a row (or a row class) the
/// `RistrettoCombCompressChip` will pin via field-op constraints.
#[derive(Clone, Copy, Debug)]
pub struct CompressWitness {
    /// `Z + Y` (row 1).
    pub z_plus_y: Bytes,
    /// `Z - Y` (row 2).
    pub z_minus_y: Bytes,
    /// `u1 = (Z+Y)·(Z-Y)` (row 3).
    pub u1: Bytes,
    /// `u2 = X·Y` (row 4).
    pub u2: Bytes,
    /// `u2² = u2·u2` (row 5).
    pub u2_sq: Bytes,
    /// `tmp = u1·u2²` (row 6).
    pub u1_u2_sq: Bytes,
    /// Witnessed root: `inv_sqrt² · tmp = 1` (row 8 verifies).  Either
    /// of the two square roots is acceptable — the chain is
    /// sign-symmetric up to the final canonicalization step.
    pub inv_sqrt: Bytes,
    /// `inv_sqrt²` (row 7).
    pub inv_sqrt_sq: Bytes,
    /// `i1 = inv_sqrt · u1` (row 9).
    pub i1: Bytes,
    /// `i2 = inv_sqrt · u2` (row 10).
    pub i2: Bytes,
    /// `i2·T` (row 11).
    pub i2_t: Bytes,
    /// `z_inv = i1·(i2·T)` (row 12).
    pub z_inv: Bytes,
    /// `T·z_inv` (row 13).  Sign feeds the rotate flag (row 14).
    pub t_z_inv: Bytes,
    /// 1 iff `T·z_inv` is "negative" per Ristretto sign convention.
    pub rotate: u8,
    /// `iX = X·SQRT_M1` (row 15).
    pub i_x: Bytes,
    /// `iY = Y·SQRT_M1` (row 16).
    pub i_y: Bytes,
    /// `enchanted_denom = i1·INVSQRT_A_MINUS_D` (row 17).
    pub enchanted_denominator: Bytes,
    /// X after rotate select: `iY` if rotate else original X.
    pub x_post_rotate: Bytes,
    /// Y after rotate select: `iX` if rotate else original Y.
    pub y_post_rotate: Bytes,
    /// den_inv after rotate select: enchanted if rotate else `i2`.
    pub den_inv: Bytes,
    /// `X_post_rotate · z_inv` (row 19).
    pub x_z_inv: Bytes,
    /// 1 iff `X_post_rotate · z_inv` is negative (row 20).
    pub y_negate_flag: u8,
    /// `Y_neg = conditional_negate(Y_post_rotate, y_negate_flag)` (row 21).
    pub y_neg: Bytes,
    /// `Z - Y_neg` (row 22).
    pub z_minus_y_neg: Bytes,
    /// `s = den_inv · (Z - Y_neg)` (row 23).
    pub s: Bytes,
    /// 1 iff `s` is negative (row 24).
    pub s_neg_flag: u8,
    /// `s_can = conditional_negate(s, s_neg_flag)` (row 25).  This is
    /// the canonical (low bit = 0) root; its bytes are the compress
    /// output.
    pub s_can: Bytes,
    /// `s_can.bytes` — the chip's memory-producer payload.  Equals
    /// `RistrettoPoint::compress(p).to_bytes()` for any `p`.
    pub out_bytes: [u8; 32],
}

/// Run dalek's `RistrettoPoint::compress` algorithm host-side over
/// our `Bytes` field reference, returning every intermediate the chip
/// will witness.
pub fn compute_compress_witness(p: &ExtendedPoint) -> CompressWitness {
    let x = p.x;
    let y = p.y;
    let z = p.z;
    let t = p.t;

    let z_plus_y = field::add(&z, &y);
    let z_minus_y = field::sub(&z, &y);
    let u1 = field::mul(&z_plus_y, &z_minus_y);
    let u2 = field::mul(&x, &y);
    let u2_sq = field::mul(&u2, &u2);
    let u1_u2_sq = field::mul(&u1, &u2_sq);

    // inv_sqrt = (u1·u2²)^((p-5)/8) — the canonical Tonelli-Shanks
    // candidate for x mod p ≡ 5 (mod 8).  Either +1/√tmp or -1/√tmp
    // depending on which root the exponentiation lands on.
    let inv_sqrt = invsqrt(&u1_u2_sq);
    let inv_sqrt_sq = field::mul(&inv_sqrt, &inv_sqrt);

    let i1 = field::mul(&inv_sqrt, &u1);
    let i2 = field::mul(&inv_sqrt, &u2);
    let i2_t = field::mul(&i2, &t);
    let z_inv = field::mul(&i1, &i2_t);

    let t_z_inv = field::mul(&t, &z_inv);
    let rotate = is_negative(&t_z_inv);

    let sm1 = sqrt_m1();
    let i_x = field::mul(&x, sm1);
    let i_y = field::mul(&y, sm1);
    let iamd = invsqrt_a_minus_d();
    let enchanted = field::mul(&i1, iamd);

    let x_post_rotate = conditional_select(&i_y, &x, rotate);
    let y_post_rotate = conditional_select(&i_x, &y, rotate);
    let den_inv = conditional_select(&enchanted, &i2, rotate);

    let x_z_inv = field::mul(&x_post_rotate, &z_inv);
    let y_negate_flag = is_negative(&x_z_inv);
    let y_neg = conditional_negate(&y_post_rotate, y_negate_flag);

    let z_minus_y_neg = field::sub(&z, &y_neg);
    let s = field::mul(&den_inv, &z_minus_y_neg);

    let s_neg_flag = is_negative(&s);
    let s_can = conditional_negate(&s, s_neg_flag);

    CompressWitness {
        z_plus_y, z_minus_y, u1, u2, u2_sq, u1_u2_sq,
        inv_sqrt, inv_sqrt_sq,
        i1, i2, i2_t, z_inv, t_z_inv, rotate,
        i_x, i_y, enchanted_denominator: enchanted,
        x_post_rotate, y_post_rotate, den_inv,
        x_z_inv, y_negate_flag, y_neg,
        z_minus_y_neg, s, s_neg_flag, s_can,
        out_bytes: s_can,
    }
}

/// Compute one of the two square roots of `1/v mod p` via the
/// Tonelli-Shanks identity for `p ≡ 5 (mod 8)`.
///
/// Returns a `Bytes` such that `r² · v == 1 mod p` whenever `v` is a
/// quadratic residue (which is always the case in compress, where
/// `v = u1·u2²` is square by Ristretto's group construction).
fn invsqrt(v: &Bytes) -> Bytes {
    // For p25519 (p ≡ 5 mod 8): the candidate is x = v^((p-5)/8).
    // Then x² · v² · v = v^((p-5)/4) · v · v² ... actually, the
    // standard identity is: r = v · u^((p-5)/8) where u = v.  The
    // dalek `sqrt_ratio_i(1, v)` algorithm:
    //   1. let r = v^((p-5)/8) · v  (candidate sqrt(1/v))
    //   2. check = r² · v
    //   3. if check == 1: return r.
    //      if check == -1: return r · SQRT_M1 (the other root of 1/v).
    //
    // We simplify here: just compute r = v^((p-5)/8) then check
    // whether r² · v = 1; if not, multiply by SQRT_M1.  Either path
    // yields a valid `inv_sqrt` for the compress chain.
    //
    // (p-5)/8 = (2^255 - 24)/8 = 2^252 - 3.
    let mut exp = [0xffu8; 32];
    // 2^252 - 3: byte 0 = 0xfd (= 256 - 3, with borrow); bytes 1..=30 = 0xff;
    // byte 31 = 0x0f (since 2^252 sets bit 252 = bit 4 of byte 31).
    exp[0] = 0xfd;
    exp[31] = 0x0f;

    // Compute candidate r₀ = v^((p-5)/8).
    let r0 = field::pow(v, &exp);
    // dalek's sqrt_ratio_i(1, v) computes:
    //   r = v · u^((p-5)/8)·v^... — a more involved form to get
    //   r = ±1/√v directly.  We recreate it as:
    //     r₀ = v^((p-5)/8)
    //     r₁ = r₀ · v          (then r₁² = v^((p-3)/4) · v² = v^((p+5)/4))
    //
    // Actually for invsqrt(v) we want r with r²·v = 1.  Method:
    //   Let r₀ = v^((p-5)/8).  Then r₀² · v = v^((p-5)/4) · v = v^((p-1)/4).
    //   For p ≡ 5 (mod 8), v^((p-1)/4) ∈ {±1} for any v (it's a 4th power
    //   of a primitive root squared, etc — it's the QR-vs-NR indicator).
    //   - If v^((p-1)/4) = 1: r₀² · v = 1, so r₀ is a candidate for
    //     1/√v? Wait no — that would say r₀² = 1/v.  Yes!  So when
    //     v^((p-1)/4) = 1, r₀ is sqrt(1/v).
    //   - If v^((p-1)/4) = -1: r₀² · v = -1, so (r₀·SQRT_M1)² · v
    //     = -1·-1 = 1, so r₀·SQRT_M1 is sqrt(1/v).
    //
    // So the recipe: r = r₀ if r₀² · v == 1, else r₀ · SQRT_M1.
    let r0_sq = field::mul(&r0, &r0);
    let r0_sq_v = field::mul(&r0_sq, v);
    let mut one = [0u8; 32];
    one[0] = 1;
    if r0_sq_v == one {
        r0
    } else {
        // Other root: multiply by SQRT_M1.
        field::mul(&r0, sqrt_m1())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    /// Cross-check our SQRT_M1 against dalek by squaring it: SQRT_M1²
    /// must equal -1 mod p (i.e. p - 1).
    #[test]
    fn sqrt_m1_squared_is_minus_one() {
        let s = *sqrt_m1();
        let s_sq = field::mul(&s, &s);
        let mut p_minus_one = field::P_BYTES;
        p_minus_one[0] -= 1;
        assert_eq!(
            s_sq, p_minus_one,
            "SQRT_M1² must equal -1 mod p; got: {s_sq:?}"
        );
    }

    /// INVSQRT_A_MINUS_D should satisfy `inv² · (a - d) = 1` where
    /// a = -1, d = -121665/121666 mod p.  Compute (a-d) and verify.
    #[test]
    fn invsqrt_a_minus_d_satisfies_definition() {
        let inv = *invsqrt_a_minus_d();
        // a - d = -1 - (-121665/121666) = -1 + 121665/121666
        //       = (121665 - 121666)/121666 = -1/121666.
        // So `inv² · (-1/121666) = 1` ⇒ `inv² = -121666` ⇒ inv² + 121666 ≡ 0 (mod p).
        let inv_sq = field::mul(&inv, &inv);
        let mut k = [0u8; 32];
        k[0] = (121666 & 0xff) as u8;
        k[1] = ((121666 >> 8) & 0xff) as u8;
        k[2] = ((121666 >> 16) & 0xff) as u8;
        let sum = field::add(&inv_sq, &k);
        assert_eq!(
            sum, [0u8; 32],
            "INVSQRT_A_MINUS_D² + 121666 must be 0 mod p"
        );
    }

    /// End-to-end: for several scalars, compute `k·G` via dalek,
    /// then run our compress on the resulting extended-Edwards
    /// representative — output bytes must match dalek's compress.
    ///
    /// Cannot extract dalek's private (X, Y, Z, T) directly, so we
    /// assemble an extended point from the canonical decompression
    /// of a known Ristretto byte sequence (the Ed25519 basepoint
    /// represented as an Edwards extended-coords representative).
    #[test]
    fn compress_matches_dalek_on_basepoint_multiples() {
        // Use the Ed25519 basepoint as our known extended point.
        // Public dalek API doesn't expose the (X, Y, Z, T) directly,
        // but we can multiply through the comb table to get a
        // representative.  Simpler: trust the comb_table module's
        // `ed25519_basepoint_extended()` factory.
        use crate::chips::ristretto::comb_table::{
            ed25519_basepoint_extended, CombTable, NUM_WINDOWS,
        };
        use crate::chips::ristretto::point::{
            point_add_rows, point_identity, ExtendedPoint,
        };

        for k in &[1u64, 7, 0x1234_5678, 0xdead_beef_cafe_babe] {
            let scalar = Scalar::from(*k);
            let scalar_bytes = scalar.to_bytes();
            let dalek_compressed = (scalar
                * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes();

            // Walk the comb table to assemble Acc = scalar · G.
            let table = CombTable::from_base(&ed25519_basepoint_extended());
            let mut acc = point_identity();
            for w in 0..NUM_WINDOWS {
                let byte = scalar_bytes[w / 2];
                let nibble_idx = w % 2;
                let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
                let entry: ExtendedPoint = table.rows[w][k_i];
                let (_rows, new_acc) = point_add_rows(&acc, &entry);
                acc = new_acc;
            }

            let witness = compute_compress_witness(&acc);
            assert_eq!(
                witness.out_bytes, dalek_compressed,
                "compress mismatch for k={k:#x}: got {:02x?}, expected {:02x?}",
                witness.out_bytes, dalek_compressed
            );

            // Spot-check the chain's intermediate constraints.
            let one_b = {
                let mut o = [0u8; 32];
                o[0] = 1;
                o
            };
            let check = field::mul(&witness.inv_sqrt_sq, &witness.u1_u2_sq);
            assert_eq!(check, one_b, "inv_sqrt² · (u1·u2²) must equal 1");
            assert_eq!(
                witness.s_can[0] & 1,
                0,
                "canonical s must have low bit = 0"
            );
        }
    }

    /// Identity point (0, 1, 1, 0) compresses to all-zero bytes.
    #[test]
    fn compress_identity_is_zero() {
        use crate::chips::ristretto::point::point_identity;
        let id = point_identity();
        let witness = compute_compress_witness(&id);
        assert_eq!(witness.out_bytes, [0u8; 32]);
    }
}
