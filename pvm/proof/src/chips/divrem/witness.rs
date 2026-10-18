//! DivRemChip's witness: a division row's quotient, remainder and chains.

use crate::core::step::WORD_SIZE;
use crate::side_note::DivRemEntry;

/// The quotient and remainder a division row proves (`d ≠ 0`), as the PVM
/// defines them: truncated signed division, with `MIN / −1 = MIN` (the
/// returned overflow); floor division by `d = 2^n` for an arithmetic right
/// shift; unsigned division otherwise. A 32-bit row divides its operands'
/// low words, and its quotient and remainder are sign-extended words.
fn quotient_remainder(
    val_b: u64,
    val_d: u64,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> (u64, u64, bool) {
    if is_32bit {
        let sign_extend = |word: u32| word as i32 as i64 as u64;
        let (b, d) = (val_b as u32, val_d as u32);
        let (q, r, overflow) = if is_div_s {
            let (b, d) = (b as i32, d as i32);
            (
                b.wrapping_div(d) as u32,
                b.wrapping_rem(d) as u32,
                b == i32::MIN && d == -1,
            )
        } else if is_shar_r {
            let q = ((b as i32) >> d.trailing_zeros()) as u32;
            (q, b.wrapping_sub(q.wrapping_mul(d)), false)
        } else {
            (b / d, b % d, false)
        };
        (sign_extend(q), sign_extend(r), overflow)
    } else if is_div_s {
        let (b, d) = (val_b as i64, val_d as i64);
        (
            b.wrapping_div(d) as u64,
            b.wrapping_rem(d) as u64,
            b == i64::MIN && d == -1,
        )
    } else if is_shar_r {
        let q = ((val_b as i64) >> val_d.trailing_zeros()) as u64;
        (q, val_b.wrapping_sub(q.wrapping_mul(val_d)), false)
    } else {
        (val_b / val_d, val_b % val_d, false)
    }
}

/// The DivRemChip row of a division by `val_d` (a right shift's `2^n`),
/// the operands as the CpuChip reads them.
pub(crate) fn entry(
    val_b: u64,
    val_d: u64,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> DivRemEntry {
    let (q, r, overflow) = if val_d == 0 {
        (0, 0, false)
    } else {
        quotient_remainder(val_b, val_d, is_32bit, is_div_s, is_shar_r)
    };
    witness(val_b, val_d, q, r, overflow, is_32bit, is_div_s, is_shar_r)
}

/// A row's internal witness for the quotient `q` and remainder `r`: the
/// chains' bytes and carries, computed over the integers. A pair that does
/// not divide `val_b` yields a witness the constraints refuse.
#[allow(clippy::too_many_arguments)]
pub fn witness(
    val_b: u64,
    val_d: u64,
    q: u64,
    r: u64,
    overflow: bool,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> DivRemEntry {
    let width = if is_32bit { 4 } else { WORD_SIZE };
    let (d_bytes, q_bytes, r_bytes) = (val_d.to_le_bytes(), q.to_le_bytes(), r.to_le_bytes());
    let sign = |x: u64| ((x >> (8 * width - 1)) & 1) as u8;
    let (sign_bit_b, sign_bit_d, sign_bit_q, sign_bit_r) =
        (sign(val_b), sign(val_d), sign(q), sign(r));

    // Schoolbook: carries and high half of q·d + r over the row's width.
    let mut sum = [0u32; 16];
    for i in 0..width {
        for j in 0..width {
            sum[i + j] += q_bytes[i] as u32 * d_bytes[j] as u32;
        }
        sum[i] += r_bytes[i] as u32;
    }
    let (mut div_mul_carry, mut div_mul_carry_hi) = ([0u8; 16], [0u8; 16]);
    let mut div_corr_hi = [0u8; WORD_SIZE];
    let mut carry = 0u32;
    for k in 0..2 * width {
        let s = sum[k] + carry;
        if k >= width {
            div_corr_hi[k - width] = s as u8;
        }
        carry = s >> 8;
        div_mul_carry[k] = carry as u8;
        div_mul_carry_hi[k] = (carry >> 8) as u8;
    }

    // Signed correction chain (signed division, arithmetic shift).
    let mut div_corr_carry = [0u8; WORD_SIZE];
    if (is_div_s || is_shar_r) && val_d != 0 {
        let sign_d = sign_bit_d * is_div_s as u8;
        let mut carry = sign_bit_r as u32 + overflow as u32;
        for i in 0..width {
            let s = sign_bit_q as u32 * d_bytes[i] as u32
                + sign_d as u32 * q_bytes[i] as u32
                + 255 * sign_bit_b as u32
                + carry;
            carry = s >> 8;
            div_corr_carry[i] = carry as u8;
        }
    }

    let (div_cmp_diff, div_cmp_carry) = add_complement(d_bytes, r_bytes);
    let d_magnitude_source = if is_32bit {
        val_d as u32 as i32 as i64 as u64
    } else {
        val_d
    };
    let (abs_d, abs_d_carry) = magnitude(d_magnitude_source, sign_bit_d);
    let (abs_r, abs_r_carry) = magnitude(r, sign_bit_r);
    let (abs_cmp_diff, abs_cmp_carry) = add_complement(abs_d, abs_r);

    DivRemEntry {
        val_b,
        val_d,
        div_quotient: q,
        div_remainder: r,
        div_corr_hi,
        div_corr_carry,
        div_mul_carry,
        div_mul_carry_hi,
        div_by_zero: val_d == 0,
        is_32bit,
        is_div_s,
        is_shar_r,
        div_overflow: overflow,
        div_cmp_diff,
        div_cmp_carry,
        sign_bit_b,
        sign_bit_d,
        sign_bit_q,
        sign_bit_r,
        abs_d,
        abs_d_carry,
        abs_r,
        abs_r_carry,
        abs_cmp_diff,
        abs_cmp_carry,
    }
}

/// `x + ~y` byte by byte with carry-in 0: the bytes and carries; the top
/// carry is 1 iff `x > y`.
fn add_complement(x: [u8; 8], y: [u8; 8]) -> ([u8; 8], [u8; 8]) {
    let (mut sum, mut carries) = ([0u8; 8], [0u8; 8]);
    let mut carry = 0u16;
    for i in 0..WORD_SIZE {
        let s = x[i] as u16 + 255 - y[i] as u16 + carry;
        sum[i] = s as u8;
        carry = s >> 8;
        carries[i] = carry as u8;
    }
    (sum, carries)
}

/// `x`'s two's-complement magnitude when `sign` is set (`~x + 1`), else
/// `x`: the bytes and the negation's carries.
fn magnitude(x: u64, sign: u8) -> ([u8; 8], [u8; 8]) {
    let x = x.to_le_bytes();
    let mut carries = [0u8; 8];
    if sign == 0 {
        return (x, carries);
    }
    let mut abs = [0u8; 8];
    let mut carry = 1u16;
    for i in 0..WORD_SIZE {
        let s = 255 - x[i] as u16 + carry;
        abs[i] = s as u8;
        carry = s >> 8;
        carries[i] = carry as u8;
    }
    (abs, carries)
}

/// The Range256 values a row emits, as a multiset.
pub fn range_checked_bytes(e: &DivRemEntry) -> impl Iterator<Item = u8> + '_ {
    let q = e.div_quotient.to_le_bytes();
    let r = e.div_remainder.to_le_bytes();
    q.into_iter()
        .chain(r)
        .chain(e.div_corr_hi)
        .chain(e.div_mul_carry)
        .chain(e.div_mul_carry_hi)
        .chain(e.div_corr_carry)
        .chain(e.abs_d)
        .chain(e.abs_r)
        .chain(e.div_cmp_diff)
        .chain(e.abs_cmp_diff)
}
