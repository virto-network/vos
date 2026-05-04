//! Per-row witness builder for field arithmetic rows in the
//! RistrettoChip trace.
//!
//! Phase R1c-2 lands the column shape and the witness-fill function
//! that produces, for one host-side field operation, the byte
//! decomposition the chip's constraints (R1c-3 onwards) will pin.
//!
//! No constraints fire here yet — the chip in `mod.rs` is still the
//! R1b empty stub and `add_constraints` does nothing.  This module
//! exists so the witness side is in place, end-to-end testable
//! against the host reference in `field.rs`, before constraint blocks
//! land row-by-row.
//!
//! Each row witnesses ONE field operation.  The full chip will
//! interleave many such rows per scalar mult (R1e schedules them).

#![cfg(feature = "prover")]

use super::field::{self, Bytes};

/// One row of field-arithmetic witness data.  Lives in `SideNote`-
/// equivalent host memory until the chip's `generate_main_trace`
/// reads it and lays it into the per-column array (R1c-3+).
///
/// All byte arrays are little-endian, consistent with `field::Bytes`.
#[derive(Clone, Copy, Debug)]
pub struct FieldOpRow {
    /// Operand a (32 bytes, LE).
    pub a: Bytes,
    /// Operand b (32 bytes, LE).
    pub b: Bytes,
    /// Output a OP b (mod p), 32 bytes LE.
    pub out: Bytes,
    /// Pre-reduction byte-wise sum bytes (only meaningful for is_add).
    /// Equals a + b before the conditional `-p` step; can sit in
    /// [0, 2p).  Held as 32 bytes; the 1-bit overflow into the
    /// 33rd "byte" is `add_carry_out`.
    pub add_intermediate: Bytes,
    /// Per-position carry chain for the `a + b` sum.  Each entry is
    /// 0 or 1.  `add_carry[i]` is the carry OUT of byte position `i`
    /// (so `add_carry[31]` is the final overflow into 2²⁵⁶).
    pub add_carry: [u8; 32],
    /// 1 iff the unreduced sum was ≥ p (so the final output came from
    /// `intermediate - p`); 0 if `output = intermediate` directly.
    pub is_overflow: u8,
    /// Per-position borrow chain for the conditional `intermediate -
    /// is_overflow * p` step.  Each entry is 0 or 1.  Zero throughout
    /// when `is_overflow = 0`.
    pub sub_borrow: [u8; 32],
    /// Per-position borrow chain for the final-form `p − out − 1 ≥ 0`
    /// check.  Final entry must be 0 (the chip's constraint enforces
    /// this).  Each entry is 0 or 1.
    pub final_form_borrow: [u8; 32],
    /// Per-position borrow chain for the is_sub constraint chain
    /// `out + b ≡ a (mod p)`.  Final entry must be 0 (closure
    /// enforced by the chip).  Zero throughout on is_add rows.
    pub sub_chain_borrow: [u8; 32],
    /// R1c-4: unreduced 64-byte schoolbook product `a · b` for
    /// is_mul rows.  Bytes 0..32 are the low half; 32..64 the high
    /// half.  Zero throughout on is_add / is_sub rows.
    pub mul_product: [u8; 64],
    /// R1c-4: per-position carry chain split into 3 bytes (lo, mid,
    /// hi) per position.  full_carry[k] = mul_carry[k] + 256·mul_carry_mid[k]
    /// + 65536·mul_carry_hi[k].  At most ~21 bits / position — the
    /// hi byte is usually 0 but reserved for the maximum-density
    /// schoolbook column near k = 31.
    pub mul_carry: [u8; 64],
    pub mul_carry_mid: [u8; 64],
    pub mul_carry_hi: [u8; 64],
    /// Operation classifier — exactly one of these is 1 on a real row.
    pub is_add: u8,
    pub is_sub: u8,
    pub is_mul: u8,
    /// 0 iff this is a padding / unused row.
    pub is_real: u8,
}

impl Default for FieldOpRow {
    fn default() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 32],
            out: [0u8; 32],
            add_intermediate: [0u8; 32],
            add_carry: [0u8; 32],
            is_overflow: 0,
            sub_borrow: [0u8; 32],
            final_form_borrow: [0u8; 32],
            sub_chain_borrow: [0u8; 32],
            mul_product: [0u8; 64],
            mul_carry: [0u8; 64],
            mul_carry_mid: [0u8; 64],
            mul_carry_hi: [0u8; 64],
            is_add: 0,
            is_sub: 0,
            is_mul: 0,
            is_real: 0,
        }
    }
}

/// Build a witness row for `out = (a + b) mod p`.  Re-runs the host
/// reference to get the canonical output, then re-derives the byte-
/// wise carry chain and `is_overflow` bit so they line up with the
/// constraint chain the chip will pin in R1c-3.
pub fn fill_add(a: Bytes, b: Bytes) -> FieldOpRow {
    // Pre-condition that the chip will also enforce: a, b < p.
    debug_assert!(less_than_p(&a), "operand a must be canonical (< p)");
    debug_assert!(less_than_p(&b), "operand b must be canonical (< p)");

    let mut intermediate = [0u8; 32];
    let mut carry = [0u8; 32];
    let mut c: u16 = 0;
    for i in 0..32 {
        let v = a[i] as u16 + b[i] as u16 + c;
        intermediate[i] = (v & 0xff) as u8;
        c = v >> 8; // 0 or 1
        carry[i] = c as u8;
    }
    let carry_out = carry[31]; // 0 or 1

    // is_overflow ⇔ the unreduced sum ≥ p.  When carry_out = 1 the
    // sum is ≥ 2²⁵⁶ > p; when carry_out = 0 we still need a final
    // < p comparison on intermediate.
    let is_overflow = if carry_out != 0 || !less_than_p(&intermediate) { 1 } else { 0 };

    // Subtract p when overflow, else copy.
    let mut out = [0u8; 32];
    let mut sub_borrow = [0u8; 32];
    let mut bw: i16 = 0;
    for i in 0..32 {
        let p_i = field::P_BYTES[i] as i16 * is_overflow as i16;
        let v = intermediate[i] as i16 - p_i - bw;
        if v < 0 {
            out[i] = (v + 256) as u8;
            bw = 1;
        } else {
            out[i] = v as u8;
            bw = 0;
        }
        sub_borrow[i] = bw as u8;
    }

    // Cross-check against the standalone host reference.  If they
    // diverge here, the witness layout is the bug, not the chip.
    debug_assert_eq!(out, field::add(&a, &b),
        "witness fill diverged from field::add reference");

    // Final-form check witness: byte-wise compute `p − out − 1` with a
    // borrow chain.  If `out < p` the result is non-negative and the
    // final borrow is 0.  If `out ≥ p` the final borrow is 1, which
    // the chip's constraint will reject.
    let mut final_form_borrow = [0u8; 32];
    let mut bw: i16 = 1; // start with -1 to compute p - out - 1
    for i in 0..32 {
        let v = field::P_BYTES[i] as i16 - out[i] as i16 - bw;
        if v < 0 {
            bw = 1;
        } else {
            bw = 0;
        }
        final_form_borrow[i] = bw as u8;
    }
    debug_assert_eq!(final_form_borrow[31], 0,
        "final-form borrow chain ends with borrow=1, witness output ≥ p");

    FieldOpRow {
        a, b, out,
        add_intermediate: intermediate,
        add_carry: carry,
        is_overflow,
        sub_borrow,
        final_form_borrow,
        sub_chain_borrow: [0u8; 32], // unused on is_add rows
        mul_product: [0u8; 64],      // unused on is_add rows
        mul_carry: [0u8; 64],
        mul_carry_mid: [0u8; 64],
        mul_carry_hi: [0u8; 64],
        is_add: 1,
        is_sub: 0,
        is_mul: 0,
        is_real: 1,
    }
}

/// Build a witness row for `out = (a − b) mod p`.  Drives the chip's
/// `is_sub` constraint chain directly: `out + b ≡ a + is_underflow·p`
/// with a per-position borrow chain witnessing the byte arithmetic.
/// `is_underflow` rides on the same wire column the chip names
/// `IsOverflow` (reinterpreted per op flag).
pub fn fill_sub(a: Bytes, b: Bytes) -> FieldOpRow {
    debug_assert!(less_than_p(&a));
    debug_assert!(less_than_p(&b));

    let out = field::sub(&a, &b);
    let is_underflow: u8 = if !ge_bytes(&a, &b) { 1 } else { 0 };

    // Borrow chain witnessing `a[i] + is_underflow·p[i]
    //   + 256·brw[i] − out[i] − b[i] − brw[i−1] = 0`.
    //
    // Equivalently `(out + b) − (a + is_underflow·p)` is balanced
    // byte-wise with brw[i] tracking the carry-out into the next
    // position.  Since the integer equality holds (and operands are
    // all < p < 2²⁵⁵), the final brw[31] is 0.
    let mut sub_chain_borrow = [0u8; 32];
    let mut brw_in: i32 = 0;
    for i in 0..32 {
        let lhs = (a[i] as i32) + (is_underflow as i32) * (field::P_BYTES[i] as i32) - brw_in;
        let rhs = (out[i] as i32) + (b[i] as i32);
        // brw_out picks the right multiple of 256 to make lhs + 256·brw_out = rhs.
        // I.e. brw_out = (rhs − lhs) / 256 ∈ {0, 1} when operands are well-formed.
        let diff = rhs - lhs;
        let brw_out = if diff < 0 { 0 } else { diff / 256 };
        debug_assert!((0..=1).contains(&brw_out),
            "sub_chain_borrow out of {{0,1}} at position {i}: diff={diff}");
        sub_chain_borrow[i] = brw_out as u8;
        brw_in = brw_out;
    }
    debug_assert_eq!(sub_chain_borrow[31], 0,
        "sub_chain_borrow chain didn't close at position 31");

    // Final-form chain (out < p) — same as fill_add, since out is
    // shared.
    let mut final_form_borrow = [0u8; 32];
    let mut bw: i16 = 1;
    for i in 0..32 {
        let v = field::P_BYTES[i] as i16 - out[i] as i16 - bw;
        bw = if v < 0 { 1 } else { 0 };
        final_form_borrow[i] = bw as u8;
    }
    debug_assert_eq!(final_form_borrow[31], 0);

    debug_assert_eq!(out, field::sub(&a, &b));

    FieldOpRow {
        a, b, out,
        // is_add columns left zero on is_sub rows.
        add_intermediate: [0u8; 32],
        add_carry: [0u8; 32],
        sub_borrow: [0u8; 32],
        is_overflow: is_underflow,
        final_form_borrow,
        sub_chain_borrow,
        mul_product: [0u8; 64],      // unused on is_sub rows
        mul_carry: [0u8; 64],
        mul_carry_mid: [0u8; 64],
        mul_carry_hi: [0u8; 64],
        is_add: 0,
        is_sub: 1,
        is_mul: 0,
        is_real: 1,
    }
}

/// True iff `a >= b` (both 32-byte LE).
fn ge_bytes(a: &Bytes, b: &Bytes) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Greater => return true,
            core::cmp::Ordering::Less => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    true
}

/// Build a witness row for `out = (a · b)` (UN-reduced — the post-
/// reduction `(a · b) mod p` lands in a R1c-5 row).
///
/// The output stored in `FieldOpRow.out` is the LOW 32 bytes of the
/// unreduced product, but soundness only enforces correctness against
/// the full 64-byte `mul_product` chain.  R1c-5 reduces those 64
/// bytes to a canonical 32-byte field element via the `2²⁵⁵ ≡ 19`
/// fold, after which `field::mul(&a, &b)` is the right cross-check.
///
/// The schoolbook carry is split into 3 bytes (lo, mid, hi) per
/// position; we precompute and emit all three so the chip's
/// constraint chain can re-witness the per-position partial-product
/// sum.
pub fn fill_mul(a: Bytes, b: Bytes) -> FieldOpRow {
    debug_assert!(less_than_p(&a));
    debug_assert!(less_than_p(&b));

    // Schoolbook over u32 partial sums (each position accumulates
    // up to 32 byte-products, so up to ~32 · 65025 ≈ 2M ≈ 21 bits;
    // u32 has plenty of headroom).
    let mut prod = [0u32; 64];
    for i in 0..32 {
        for j in 0..32 {
            prod[i + j] += (a[i] as u32) * (b[j] as u32);
        }
    }

    // Carry-propagate so each output byte fits in [0, 256).
    let mut mul_product = [0u8; 64];
    let mut mul_carry = [0u8; 64];
    let mut mul_carry_mid = [0u8; 64];
    let mut mul_carry_hi = [0u8; 64];
    let mut full_carry: u32 = 0;
    for k in 0..64 {
        let v = prod[k] + full_carry;
        mul_product[k] = (v & 0xff) as u8;
        let new_carry = v >> 8;
        mul_carry[k]     = (new_carry & 0xff) as u8;
        mul_carry_mid[k] = ((new_carry >> 8) & 0xff) as u8;
        mul_carry_hi[k]  = ((new_carry >> 16) & 0xff) as u8;
        full_carry = new_carry;
    }
    debug_assert_eq!(full_carry, 0, "schoolbook chain didn't close at position 63");

    let mut out = [0u8; 32];
    out.copy_from_slice(&mul_product[..32]);

    FieldOpRow {
        a, b, out,
        // is_add / is_sub witness fields zero on is_mul rows.
        add_intermediate: [0u8; 32],
        add_carry: [0u8; 32],
        is_overflow: 0,
        sub_borrow: [0u8; 32],
        final_form_borrow: [0u8; 32],
        sub_chain_borrow: [0u8; 32],
        mul_product,
        mul_carry,
        mul_carry_mid,
        mul_carry_hi,
        is_add: 0,
        is_sub: 0,
        is_mul: 1,
        is_real: 1,
    }
}

/// Padding row (all zeros, `is_real = 0`).  Constraint blocks gate
/// off via `is_real * (...)` so padding rows are inert.
pub fn fill_padding() -> FieldOpRow {
    FieldOpRow::default()
}

/// True iff `a` (32 bytes LE) is strictly less than p = 2²⁵⁵-19.
/// Used as a witness pre-condition; the chip will pin canonicality at
/// the boundary lookup (R1e).
fn less_than_p(a: &Bytes) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&field::P_BYTES[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    false // equal to p ⇒ not strictly less
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(v: u8) -> Bytes {
        let mut b = [0u8; 32]; b[0] = v; b
    }

    #[test]
    fn fill_add_small() {
        let row = fill_add(small(7), small(13));
        assert_eq!(row.is_add, 1);
        assert_eq!(row.is_real, 1);
        assert_eq!(row.out[0], 20);
        assert_eq!(row.is_overflow, 0);
        assert!(row.add_carry.iter().all(|&c| c == 0));
    }

    #[test]
    fn fill_add_overflow_at_p() {
        // (p-1) + 2 ≡ 1 (mod p) — exercises the `is_overflow=1` branch.
        let p_minus_one = {
            let mut t = field::P_BYTES;
            t[0] -= 1;
            t
        };
        let row = fill_add(p_minus_one, small(2));
        assert_eq!(row.is_overflow, 1);
        assert_eq!(row.out, small(1), "(p-1) + 2 ≡ 1 (mod p)");
    }

    #[test]
    fn fill_add_carry_chain_consistency() {
        // Pick operands that produce a multi-position carry to sanity-
        // check the chain matches the constraint we'll write later.
        let mut a = [0u8; 32];
        for i in 0..16 { a[i] = 0xff; }
        let mut b = [0u8; 32];
        b[0] = 1;
        // a is < p (high bytes are 0); b is < p.  a + b carries
        // through positions 0..16, lands clean in position 16.
        let row = fill_add(a, b);
        // Re-derive the constraint we'll pin: out[i] + 256*carry[i] =
        // a[i] + b[i] + carry[i-1], with carry[-1] = 0 and
        // is_overflow*p reductions absorbed AFTER the chain.
        let mut prev_carry = 0u16;
        for i in 0..32 {
            let lhs = row.add_intermediate[i] as u16 + 256 * row.add_carry[i] as u16;
            let rhs = a[i] as u16 + b[i] as u16 + prev_carry;
            assert_eq!(lhs, rhs, "carry chain breaks at position {i}");
            prev_carry = row.add_carry[i] as u16;
        }
    }

    #[test]
    fn fill_sub_round_trip() {
        let a = small(50);
        let b = small(12);
        let row = fill_sub(a, b);
        assert_eq!(row.is_sub, 1);
        assert_eq!(row.out[0], 38);
    }

    #[test]
    fn fill_sub_underflow_wraps() {
        // 5 - 10 ≡ p - 5 (mod p).
        let row = fill_sub(small(5), small(10));
        let expected = field::sub(&small(5), &small(10));
        assert_eq!(row.out, expected);
    }

    #[test]
    fn fill_mul_small_produces_unreduced_product() {
        // 7 · 13 = 91; low byte of mul_product should be 91, all
        // higher bytes 0.
        let row = fill_mul(small(7), small(13));
        assert_eq!(row.is_mul, 1);
        assert_eq!(row.mul_product[0], 91);
        for i in 1..64 { assert_eq!(row.mul_product[i], 0); }
        assert_eq!(row.out[0], 91);
    }

    #[test]
    fn fill_mul_chain_closes_for_random_inputs() {
        // Use mid-range bytes so partial products near k=31 hit
        // their max density and the carry chain exercises hi byte.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        for i in 0..32 { a[i] = (0xa3u8).wrapping_mul((i + 1) as u8); }
        for i in 0..32 { b[i] = (0x71u8).wrapping_mul((i + 1) as u8); }
        a[31] &= 0x7f; // canonical
        b[31] &= 0x7f;
        let row = fill_mul(a, b);

        // Re-derive the schoolbook chain: prod[k] = Σ_{i+j=k} a[i]·b[j],
        // carry-propagated so each byte fits in [0, 256).  Cross-check
        // against the witness.
        let mut prod = [0u64; 64];
        for i in 0..32 {
            for j in 0..32 {
                prod[i + j] += (a[i] as u64) * (b[j] as u64);
            }
        }
        let mut full_carry: u64 = 0;
        for k in 0..64 {
            let v = prod[k] + full_carry;
            assert_eq!(row.mul_product[k] as u64, v & 0xff,
                "mul_product diverges at position {k}");
            let new_carry = v >> 8;
            let reconstructed = row.mul_carry[k] as u32
                + 256 * row.mul_carry_mid[k] as u32
                + 65536 * row.mul_carry_hi[k] as u32;
            assert_eq!(reconstructed as u64, new_carry,
                "carry split mismatched at position {k}");
            full_carry = new_carry;
        }
        assert_eq!(full_carry, 0, "chain must close at position 63");
    }
}
