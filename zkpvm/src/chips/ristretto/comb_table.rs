//! Session 2.1 of the perf roadmap — comb-method scaffolding for
//! Ristretto fixed-base scalar multiplication.
//!
//! This module is host-side only.  It precomputes the per-base
//! lookup table `T[64][16]` and exposes a reference
//! `scalar_mult_via_comb` that produces the same point as
//! `point::scalar_mult_rows`, but at ~63 point-ops per mult vs ~384.
//!
//! Layout: `T[i][j] = j · 2^(4·i) · base` for `i ∈ 0..64`, `j ∈ 0..16`.
//! 64 windows × 16 entries = 1024 ExtendedPoints per fixed base.
//!
//! Scalar split: little-endian 4-bit windows.  Window `i` is the
//! `i`-th nibble: `k_i = (scalar[i/2] >> (4·(i%2))) & 0xF`.
//!
//! The chip-side integration (preprocessed columns + lookup
//! constraint + new fixed-base row class) is the next-larger
//! deliverable for Session 2.1; this module's role is to pin down
//! the precompute math first so the chip side has a host-side
//! reference that's already cross-checked against the existing
//! double-and-add path.

#![cfg(feature = "prover")]

use alloc::vec::Vec;

use super::field::{self, Bytes};
use super::point::{ExtendedPoint, point_add_rows, point_double_rows, point_identity};

pub const WINDOW_BITS: usize = 4;
pub const NUM_WINDOWS: usize = 64;
pub const WINDOW_SIZE: usize = 1 << WINDOW_BITS;

/// One row of the comb table: 16 multiples of `2^(4·i) · base`.
pub type CombRow = [ExtendedPoint; WINDOW_SIZE];

/// Full comb table for one fixed base: 64 rows × 16 entries.
pub struct CombTable {
    pub rows: Vec<CombRow>,
}

impl CombTable {
    /// Compute `T[i][j] = j · 2^(4·i) · base` for all `(i, j)`.
    ///
    /// Cost: O(NUM_WINDOWS × WINDOW_SIZE) point-adds + O(NUM_WINDOWS
    /// × WINDOW_BITS) doublings at host build time.  Runs once per
    /// base; the chip stores the result as preprocessed columns so
    /// runtime cost is amortised across every scalar mult.
    pub fn from_base(base: &ExtendedPoint) -> Self {
        let mut rows = Vec::with_capacity(NUM_WINDOWS);
        // After window i, `current` holds `2^(4·i) · base`.
        let mut current = *base;
        for _ in 0..NUM_WINDOWS {
            let mut row = [point_identity(); WINDOW_SIZE];
            // T[i][0] = identity; T[i][j] = T[i][j-1] + current.
            for j in 1..WINDOW_SIZE {
                let (_, sum) = point_add_rows(&row[j - 1], &current);
                row[j] = sum;
            }
            rows.push(row);
            // Advance: current ← current · 2^WINDOW_BITS via repeated doublings.
            for _ in 0..WINDOW_BITS {
                let (_, doubled) = point_double_rows(&current);
                current = doubled;
            }
        }
        CombTable { rows }
    }
}

/// Compute `k · base` via the comb method given a precomputed table.
///
/// Cost: NUM_WINDOWS table lookups (free, table-read) + NUM_WINDOWS
/// point adds.  ~6× fewer chip rows per scalar mult than
/// `point::scalar_mult_rows` (256 doublings + ~128 adds).
pub fn scalar_mult_via_comb(table: &CombTable, scalar: &Bytes) -> ExtendedPoint {
    let mut acc = point_identity();
    for i in 0..NUM_WINDOWS {
        let byte = scalar[i / 2];
        let nibble_idx = i % 2;
        let k_i = ((byte >> (nibble_idx * WINDOW_BITS)) & 0x0F) as usize;
        let entry = &table.rows[i][k_i];
        let (_, sum) = point_add_rows(&acc, entry);
        acc = sum;
    }
    acc
}

/// Ed25519 basepoint in extended Edwards coords.  RFC 8032 §5.1:
/// `y = 4/5 mod p`, `x` is the canonical positive root (LSB of x = 0).
/// `Z = 1`, `T = x · y`.
///
/// This is also the canonical Ristretto255 basepoint (Ristretto is a
/// quotient of the Edwards group; scalar mult acts identically).
pub fn ed25519_basepoint_extended() -> ExtendedPoint {
    // x in little-endian bytes (BE: 0x216936D3...0F25D51A).
    let x: Bytes = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c,
        0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36,
        0x69, 0x21,
    ];
    // y in little-endian bytes (BE: 0x66666666...66666658) = 4/5 mod p.
    let y: Bytes = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    let z: Bytes = {
        let mut o = [0u8; 32];
        o[0] = 1;
        o
    };
    let t = field::mul(&x, &y);
    ExtendedPoint { x, y, z, t }
}

#[cfg(test)]
mod tests {
    use super::super::point::scalar_mult_rows;
    use super::*;

    /// Cross-multiplication equality on extended-coords projective points.
    fn projective_eq(p: &ExtendedPoint, q: &ExtendedPoint) -> bool {
        field::mul(&p.x, &q.z) == field::mul(&q.x, &p.z)
            && field::mul(&p.y, &q.z) == field::mul(&q.y, &p.z)
    }

    #[test]
    fn basepoint_y_is_4_over_5() {
        let bp = ed25519_basepoint_extended();
        let y_norm = field::mul(&bp.y, &field::inv(&bp.z));
        let four = {
            let mut b = [0u8; 32];
            b[0] = 4;
            b
        };
        let five = {
            let mut b = [0u8; 32];
            b[0] = 5;
            b
        };
        let expected = field::mul(&four, &field::inv(&five));
        assert_eq!(y_norm, expected);
    }

    #[test]
    fn basepoint_t_is_xy() {
        let bp = ed25519_basepoint_extended();
        // T = x · y / z, but z = 1 so T = x · y.
        assert_eq!(bp.t, field::mul(&bp.x, &bp.y));
    }

    #[test]
    fn comb_row0_seeds_match_base() {
        let bp = ed25519_basepoint_extended();
        let table = CombTable::from_base(&bp);
        // T[0][0] = identity
        assert!(projective_eq(&table.rows[0][0], &point_identity()));
        // T[0][1] = 1 · 2^0 · base = base
        assert!(projective_eq(&table.rows[0][1], &bp));
        // T[0][2] = 2 · base = base + base
        let (_, two_bp) = point_add_rows(&bp, &bp);
        assert!(projective_eq(&table.rows[0][2], &two_bp));
        // T[0][15] = 15 · base
        let mut acc = bp;
        for _ in 1..15 {
            let (_, s) = point_add_rows(&acc, &bp);
            acc = s;
        }
        assert!(projective_eq(&table.rows[0][15], &acc));
    }

    #[test]
    fn comb_row1_advances_by_2_to_4() {
        // T[1][1] = 16 · base = 2^4 · base
        let bp = ed25519_basepoint_extended();
        let table = CombTable::from_base(&bp);
        let mut acc = bp;
        // Compute 2^4 · base via four doublings.
        for _ in 0..4 {
            let (_, d) = point_double_rows(&acc);
            acc = d;
        }
        assert!(projective_eq(&table.rows[1][1], &acc));
    }

    #[test]
    fn comb_matches_double_and_add_small_scalar() {
        let bp = ed25519_basepoint_extended();
        let table = CombTable::from_base(&bp);
        let scalar: Bytes = {
            let mut s = [0u8; 32];
            s[0] = 7;
            s
        };
        let comb_result = scalar_mult_via_comb(&table, &scalar);
        let (_, dad_result) = scalar_mult_rows(&scalar, &bp);
        assert!(projective_eq(&comb_result, &dad_result));
    }

    #[test]
    fn comb_matches_double_and_add_random_scalars() {
        let bp = ed25519_basepoint_extended();
        let table = CombTable::from_base(&bp);
        // Deterministic pseudo-random scalars.
        for seed in 0u64..5 {
            let mut scalar = [0u8; 32];
            for i in 0..32 {
                scalar[i] = ((seed
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(i as u64 * 31))
                    & 0xff) as u8;
            }
            // Mask off the highest bit so we stay below 2^255 (and well below curve order).
            scalar[31] &= 0x7F;
            let comb_result = scalar_mult_via_comb(&table, &scalar);
            let (_, dad_result) = scalar_mult_rows(&scalar, &bp);
            assert!(
                projective_eq(&comb_result, &dad_result),
                "comb ≠ double-and-add on seed {seed}"
            );
        }
    }
}
