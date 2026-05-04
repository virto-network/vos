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
    /// Operation classifier — exactly one of these is 1 on a real row.
    pub is_add: u8,
    pub is_sub: u8,
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
            is_add: 0,
            is_sub: 0,
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

    FieldOpRow {
        a, b, out,
        add_intermediate: intermediate,
        add_carry: carry,
        is_overflow,
        sub_borrow,
        is_add: 1,
        is_sub: 0,
        is_real: 1,
    }
}

/// Build a witness row for `out = (a - b) mod p`.  Mirror of
/// `fill_add` for completeness; constraint pinning lands in R1c-3.
pub fn fill_sub(a: Bytes, b: Bytes) -> FieldOpRow {
    debug_assert!(less_than_p(&a));
    debug_assert!(less_than_p(&b));

    // Implementation: out = a + (p - b) (mod p), so we can re-use the
    // adder chain and witness shape.  The chip will instead constrain
    // `out + b ≡ a (mod p)` directly via a sub carry chain, but the
    // host fill can take the lazy path because it just needs to
    // produce values consistent with `field::sub`.
    let p_minus_b = {
        let mut t = [0u8; 32];
        let mut bw: i16 = 0;
        for i in 0..32 {
            let v = field::P_BYTES[i] as i16 - b[i] as i16 - bw;
            if v < 0 { t[i] = (v + 256) as u8; bw = 1; }
            else     { t[i] = v as u8; bw = 0; }
        }
        t
    };
    let mut row = fill_add(a, p_minus_b);
    row.is_add = 0;
    row.is_sub = 1;
    debug_assert_eq!(row.out, field::sub(&a, &b),
        "witness fill_sub diverged from field::sub reference");
    row
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
}
