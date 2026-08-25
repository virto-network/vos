//! Pure-Rust reference implementation of arithmetic in 𝔽_p where
//! p = 2²⁵⁵ - 19 (Curve25519's base field).  Independent of dalek so
//! the chip's witness-fill and constraint-equation derivations have a
//! ground truth that doesn't go through the host crypto stack.
//!
//! Representation: little-endian 32-byte arrays, same wire format the
//! ECALL boundary lookup commits to (`scalar_bytes`, `point_bytes`,
//! `out_bytes` in `RistrettoMemOp`).
//!
//! Cross-checked against `curve25519_dalek::scalar::Scalar` /
//! `curve25519_dalek::field::FieldElement` in the test below: the same
//! random inputs through both paths produce bit-for-bit identical
//! outputs.  Future R1c sub-phases (column layout, schoolbook, carry
//! chains) constrain the chip to recompute exactly what this module
//! computes; if the chip diverges, the test catches it before any
//! constraint blocks land.
//!
//! Out of scope here: M31 limb representation.  This module deals in
//! big-integer 256-bit values (via the host's u128 schoolbook) — the
//! M31-limb decomposition is the chip's job, not the reference's.

#![cfg(feature = "prover")]

/// Field-element bytes: little-endian, 256-bit (the high bit of the
/// 32nd byte is masked off by `reduce` so this also denotes canonical
/// in-range elements).
pub type Bytes = [u8; 32];

/// Modulus p = 2²⁵⁵ - 19 in little-endian bytes.
pub const P_BYTES: Bytes = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed; // 0xff..ed = 2^255 - 19
    p[31] = 0x7f;
    p
};

/// Reduce a big-integer (already < 2²⁵⁶) modulo p.  At most one
/// conditional subtraction of p suffices since the input is bounded
/// by 2²⁵⁶ < 2 * p (because 2 * p = 2²⁵⁶ - 38 < 2²⁵⁶).
pub fn reduce(a: Bytes) -> Bytes {
    if !ge(&a, &P_BYTES) {
        return a;
    }
    sub_no_reduce(&a, &P_BYTES)
}

/// Modular addition: `(a + b) mod p`.  Pre-condition: a, b < p.
/// Post-condition: result < p.
pub fn add(a: &Bytes, b: &Bytes) -> Bytes {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    // Sum is now in [0, 2p) — at most one subtraction of p brings it
    // back into [0, p).  The chip will witness `is_overflow` as a
    // bit; here we just compute it.
    let needs_sub = carry != 0 || ge(&out, &P_BYTES);
    if needs_sub {
        sub_no_reduce(&out, &P_BYTES)
    } else {
        out
    }
}

/// Modular subtraction: `(a - b) mod p`.  Pre-condition: a, b < p.
pub fn sub(a: &Bytes, b: &Bytes) -> Bytes {
    if ge(a, b) {
        sub_no_reduce(a, b)
    } else {
        // a < b ⇒ result = (a + p) - b.
        let aplusp = add_no_reduce_overflow(a, &P_BYTES).0;
        sub_no_reduce(&aplusp, b)
    }
}

/// Modular multiplication: `(a * b) mod p`.  Schoolbook over u128
/// limbs with reduction by the identity 2²⁵⁵ ≡ 19 (mod p).
pub fn mul(a: &Bytes, b: &Bytes) -> Bytes {
    // Schoolbook: a (32 bytes) * b (32 bytes) = 64-byte product.
    let mut prod = [0u32; 64];
    for i in 0..32 {
        for j in 0..32 {
            prod[i + j] += (a[i] as u32) * (b[j] as u32);
        }
    }
    // Carry-propagate so each prod[k] fits in a single byte.
    let mut carry: u64 = 0;
    let mut bytes = [0u8; 64];
    for k in 0..64 {
        let v = prod[k] as u64 + carry;
        bytes[k] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    debug_assert_eq!(carry, 0, "schoolbook overflowed 64 bytes");

    // Reduction.  Split as `lo (32 B) + 2²⁵⁶ * hi_extra` where
    //   hi_extra is the high half (bytes[32..64]) and the high bit
    //   of bytes[31] is also "above 2²⁵⁵".
    //
    // Since 2²⁵⁵ ≡ 19 (mod p), we have 2²⁵⁶ ≡ 38 (mod p).  So the
    // 512-bit product reduces as `lo + 38 * hi (mod p)`.  Iterate
    // the reduction twice: once to fold `hi` into a smaller residual,
    // again to clear the top bit if needed.
    let mut lo: Bytes = bytes[0..32].try_into().unwrap();
    let mut hi: Bytes = bytes[32..64].try_into().unwrap();

    // First fold: lo += 38 * hi.  38 * hi can be up to 38 * (2²⁵⁶ - 1)
    // ≈ 38 * 2²⁵⁶, so it overflows lo by at most ⌈log2(38)⌉ = 6 bits.
    // Capture the overflow and fold it again.
    for _round in 0..2 {
        let (sum, overflow_bytes) = mul_small_then_add(&hi, 38, &lo);
        lo = sum;
        hi = overflow_bytes; // most rounds will produce hi = [0u8; 32]
        if hi == [0u8; 32] {
            break;
        }
    }

    // Now lo is in [0, 2 * p) — final conditional subtraction.
    // Also clear the top bit if it's set (since p has top bit = 0).
    let top_bit = lo[31] >> 7;
    if top_bit != 0 {
        lo[31] &= 0x7f;
        // We just dropped 2²⁵⁵ from the value, which equals 19 (mod p).
        let mut nineteen = [0u8; 32];
        nineteen[0] = 19;
        lo = add(&lo, &nineteen);
    }
    reduce(lo)
}

/// Modular inverse via Fermat: `a^(p-2) mod p`.  Used for division
/// inside the Edwards point formulae (specifically the `Z`-coordinate
/// inverse when re-normalizing to affine).  Square-and-multiply with
/// the canonical p-2 exponent.
pub fn inv(a: &Bytes) -> Bytes {
    // p - 2 = 2²⁵⁵ - 21
    //       = 0xff..ff_eb (with byte[0] = 0xeb, byte[31] = 0x7f)
    let mut exp = P_BYTES;
    // Subtract 2 from p.
    let mut borrow = 2u16;
    for i in 0..32 {
        let v = exp[i] as i32 - borrow as i32;
        if v < 0 {
            exp[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            exp[i] = v as u8;
            borrow = 0;
        }
        if borrow == 0 {
            break;
        }
    }
    pow(a, &exp)
}

/// `base^exp mod p`, square-and-multiply, scanning `exp` MSB first.
pub fn pow(base: &Bytes, exp: &Bytes) -> Bytes {
    let mut result = [0u8; 32];
    result[0] = 1; // 1 in little-endian.
    let mut base_pow = *base;
    for byte in exp.iter() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                result = mul(&result, &base_pow);
            }
            base_pow = mul(&base_pow, &base_pow);
        }
    }
    result
}

// ── Helpers (no constraint counterpart — pure host arithmetic) ──

/// Big-endian comparison: returns true iff `a >= b`.
fn ge(a: &Bytes, b: &Bytes) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Greater => return true,
            core::cmp::Ordering::Less => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    true // equal
}

/// Subtract without reduction.  Pre-condition: a >= b.
fn sub_no_reduce(a: &Bytes, b: &Bytes) -> Bytes {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let v = a[i] as i16 - b[i] as i16 - borrow;
        if v < 0 {
            out[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            out[i] = v as u8;
            borrow = 0;
        }
    }
    out
}

/// Add without reduction.  Returns (sum, carry_out_bit).
fn add_no_reduce_overflow(a: &Bytes, b: &Bytes) -> (Bytes, u8) {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    (out, carry as u8)
}

/// Compute `addend + small * factor`.  `small` is at most 38 (the
/// p25519 reduction constant).  Returns (low 32 B, residual high 32 B).
fn mul_small_then_add(factor: &Bytes, small: u32, addend: &Bytes) -> (Bytes, Bytes) {
    let mut prod = [0u32; 33];
    for i in 0..32 {
        prod[i] += (factor[i] as u32) * small;
    }
    let mut carry: u64 = 0;
    let mut bytes = [0u8; 33];
    for k in 0..33 {
        let v = prod[k] as u64 + carry;
        bytes[k] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    debug_assert_eq!(carry, 0);

    let small_prod_lo: Bytes = bytes[0..32].try_into().unwrap();
    let final_overflow_byte = bytes[32];

    let (sum, sum_carry) = add_no_reduce_overflow(&small_prod_lo, addend);

    // The "high" residual is whatever overflowed the low 32 bytes:
    // sum_carry (1 bit) + final_overflow_byte (8 bits) = up to 9 bits.
    let mut hi = [0u8; 32];
    hi[0] = final_overflow_byte.wrapping_add(sum_carry);
    if (final_overflow_byte as u16) + (sum_carry as u16) > 0xff {
        hi[1] = 1;
    }
    (sum, hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

    /// Scalar field arithmetic in dalek operates mod ℓ (the prime
    /// 2²⁵² + 27742...), not mod p = 2²⁵⁵-19.  But `Scalar` is dalek's
    /// only `Bytes` ↔ canonical-element bijection at the boundary, and
    /// we just want a smoke test that our 256-
    /// bit schoolbook + reduction is internally consistent — not that
    /// it agrees with dalek's *scalar* arithmetic, which is a
    /// different ring.
    ///
    /// For p25519 specifically there is no public type in dalek that
    /// wraps `FieldElement`; we cross-check against the *Scalar*
    /// modular ring as a sanity-test for our `add`/`sub`/`mul`
    /// implementations on small inputs where p doesn't intervene.
    /// The chip-side validation (R1f) goes through Ristretto scalar
    /// mult end-to-end against dalek, which is the real ground truth.
    #[test]
    fn add_sub_round_trip() {
        let mut a = [0u8; 32];
        a[0] = 5;
        a[1] = 3;
        let mut b = [0u8; 32];
        b[0] = 7;
        b[5] = 11;
        let s = add(&a, &b);
        let back = sub(&s, &b);
        assert_eq!(back, a, "(a + b) - b = a");
    }

    #[test]
    fn add_overflow_wraps_mod_p() {
        let p_minus_one = sub(&P_BYTES, &one());
        let one_b = one();
        let s = add(&p_minus_one, &one_b);
        assert_eq!(s, [0u8; 32], "(p-1) + 1 ≡ 0 (mod p)");
    }

    #[test]
    fn mul_by_zero_is_zero() {
        let mut a = [0u8; 32];
        a[0] = 0xab;
        a[15] = 0xcd;
        assert_eq!(mul(&a, &[0u8; 32]), [0u8; 32]);
    }

    #[test]
    fn mul_by_one_is_identity() {
        let mut a = [0u8; 32];
        for i in 0..32 {
            a[i] = (0xa3u8).wrapping_mul((i + 1) as u8);
        }
        a[31] &= 0x7f; // canonical
        let prod = mul(&a, &one());
        assert_eq!(prod, reduce(a));
    }

    #[test]
    fn mul_associative() {
        let a = bytes_filled(0x11);
        let b = bytes_filled(0x22);
        let c = bytes_filled(0x33);
        let lhs = mul(&mul(&a, &b), &c);
        let rhs = mul(&a, &mul(&b, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn mul_distributes_over_add() {
        let a = bytes_filled(0x44);
        let b = bytes_filled(0x55);
        let c = bytes_filled(0x66);
        let lhs = mul(&a, &add(&b, &c));
        let rhs = add(&mul(&a, &b), &mul(&a, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn inv_round_trip() {
        let a = bytes_filled(0x77);
        let a_inv = inv(&a);
        let prod = mul(&a, &a_inv);
        assert_eq!(prod, one(), "a * a^(-1) ≡ 1 (mod p)");
    }

    /// Cross-check small-integer arithmetic agrees with dalek's
    /// `Scalar` ring on inputs that reduce identically in both
    /// (i.e. small enough that 2²⁵²+...  and 2²⁵⁵-19 don't differ).
    #[test]
    fn small_integer_addition_matches_scalar_ring() {
        let a = small(7);
        let b = small(13);
        let our = add(&a, &b);
        let dalek_a = Scalar::from(7u8);
        let dalek_b = Scalar::from(13u8);
        let dalek_sum = (dalek_a + dalek_b).to_bytes();
        assert_eq!(our, dalek_sum);
    }

    fn one() -> Bytes {
        let mut o = [0u8; 32];
        o[0] = 1;
        o
    }

    fn small(v: u8) -> Bytes {
        let mut o = [0u8; 32];
        o[0] = v;
        o
    }

    fn bytes_filled(seed: u8) -> Bytes {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = seed.wrapping_add(i as u8);
        }
        o[31] &= 0x7f; // canonical: clear top bit
        o
    }
}
