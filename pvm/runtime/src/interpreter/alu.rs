//! The register results of the division, remainder and upper-multiply
//! instructions (Gray Paper v0.8.0, A.5.13), shared by [`super::Interpreter::step`]
//! and the predecoded run loop. Each takes φ_A and φ_B and returns φ′_D.

use crate::args::sign_extend_32;

#[inline(always)]
pub(super) fn div_u_32(a: u64, b: u64) -> u64 {
    (a as u32)
        .checked_div(b as u32)
        .map_or(u64::MAX, |q| sign_extend_32(q as u64))
}

#[inline(always)]
pub(super) fn div_s_32(a: u64, b: u64) -> u64 {
    let (a, b) = (a as i32, b as i32);
    if b == 0 {
        u64::MAX
    } else if a == i32::MIN && b == -1 {
        a as i64 as u64
    } else {
        (a / b) as i64 as u64
    }
}

#[inline(always)]
pub(super) fn rem_u_32(a: u64, b: u64) -> u64 {
    let (a, b) = (a as u32, b as u32);
    sign_extend_32(a.checked_rem(b).unwrap_or(a) as u64)
}

/// Rust's remainder takes the dividend's sign, as smod does.
#[inline(always)]
pub(super) fn rem_s_32(a: u64, b: u64) -> u64 {
    let (a, b) = (a as i32, b as i32);
    if b == 0 {
        a as i64 as u64
    } else if a == i32::MIN && b == -1 {
        0
    } else {
        (a % b) as i64 as u64
    }
}

#[inline(always)]
pub(super) fn div_u_64(a: u64, b: u64) -> u64 {
    a.checked_div(b).unwrap_or(u64::MAX)
}

#[inline(always)]
pub(super) fn div_s_64(a: u64, b: u64) -> u64 {
    let (a, b) = (a as i64, b as i64);
    if b == 0 {
        u64::MAX
    } else if a == i64::MIN && b == -1 {
        a as u64
    } else {
        (a / b) as u64
    }
}

#[inline(always)]
pub(super) fn rem_u_64(a: u64, b: u64) -> u64 {
    a.checked_rem(b).unwrap_or(a)
}

/// Rust's remainder takes the dividend's sign, as smod does.
#[inline(always)]
pub(super) fn rem_s_64(a: u64, b: u64) -> u64 {
    let (a, b) = (a as i64, b as i64);
    if b == 0 {
        a as u64
    } else if a == i64::MIN && b == -1 {
        0
    } else {
        (a % b) as u64
    }
}

#[inline(always)]
pub(super) fn mul_upper_s_s(a: u64, b: u64) -> u64 {
    ((a as i64 as i128 * b as i64 as i128) >> 64) as u64
}

#[inline(always)]
pub(super) fn mul_upper_u_u(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) >> 64) as u64
}

#[inline(always)]
pub(super) fn mul_upper_s_u(a: u64, b: u64) -> u64 {
    ((a as i64 as i128 * b as i128) >> 64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_64: i128 = 1 << 64;

    /// Z_n: the signed reading of an n-byte value.
    fn signed(x: u64, bytes: u32) -> i128 {
        let modulus = 1i128 << (8 * bytes);
        let x = x as i128 % modulus;
        if x >= modulus / 2 { x - modulus } else { x }
    }

    /// Z_8^-1.
    fn unsigned(x: i128) -> u64 {
        x.rem_euclid(TWO_64) as u64
    }

    /// X_4: sign extension of the low four bytes.
    fn sext4(x: u64) -> u64 {
        unsigned(signed(x % (1 << 32), 4))
    }

    /// smod: the absolute remainder with the dividend's sign.
    fn smod(a: i128, b: i128) -> i128 {
        if b == 0 {
            a
        } else {
            a.signum() * (a.abs() % b.abs())
        }
    }

    type Op = fn(u64, u64) -> u64;

    /// The A.5.13 rules as written, over unbounded integers.
    fn oracle(name: &str, a: u64, b: u64) -> u64 {
        let (a32, b32) = (a % (1 << 32), b % (1 << 32));
        let (sa32, sb32) = (signed(a, 4), signed(b, 4));
        let (sa, sb) = (signed(a, 8), signed(b, 8));
        match name {
            "div_u_32" if b32 == 0 => u64::MAX,
            "div_u_32" => sext4(a32 / b32),
            "div_s_32" if sb32 == 0 => u64::MAX,
            "div_s_32" if sa32 == -(1 << 31) && sb32 == -1 => unsigned(sa32),
            "div_s_32" => unsigned(sa32 / sb32),
            "rem_u_32" if b32 == 0 => sext4(a32),
            "rem_u_32" => sext4(a32 % b32),
            "rem_s_32" if sa32 == -(1 << 31) && sb32 == -1 => 0,
            "rem_s_32" => unsigned(smod(sa32, sb32)),
            "div_u_64" if b == 0 => u64::MAX,
            "div_u_64" => a / b,
            "div_s_64" if b == 0 => u64::MAX,
            "div_s_64" if sa == -(1 << 63) && sb == -1 => a,
            "div_s_64" => unsigned(sa / sb),
            "rem_u_64" if b == 0 => a,
            "rem_u_64" => a % b,
            "rem_s_64" if sa == -(1 << 63) && sb == -1 => 0,
            "rem_s_64" => unsigned(smod(sa, sb)),
            "mul_upper_s_s" => unsigned((sa * sb).div_euclid(TWO_64)),
            "mul_upper_u_u" => ((a as u128 * b as u128) / TWO_64 as u128) as u64,
            "mul_upper_s_u" => unsigned((sa * b as i128).div_euclid(TWO_64)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn edge_values_follow_the_rules() {
        let ops: [(&str, Op); 11] = [
            ("div_u_32", div_u_32),
            ("div_s_32", div_s_32),
            ("rem_u_32", rem_u_32),
            ("rem_s_32", rem_s_32),
            ("div_u_64", div_u_64),
            ("div_s_64", div_s_64),
            ("rem_u_64", rem_u_64),
            ("rem_s_64", rem_s_64),
            ("mul_upper_s_s", mul_upper_s_s),
            ("mul_upper_u_u", mul_upper_u_u),
            ("mul_upper_s_u", mul_upper_s_u),
        ];
        let values = [
            0,
            1,
            2,
            7,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0x1_0000_0001,
            0x1_FFFF_FFFF,
            0xFFFF_FFFF_8000_0000,
            0x1234_5678_9ABC_DEF0,
            i64::MAX as u64,
            i64::MIN as u64,
            u64::MAX - 6,
            u64::MAX - 1,
            u64::MAX,
        ];
        for (name, op) in ops {
            for a in values {
                for b in values {
                    assert_eq!(op(a, b), oracle(name, a, b), "{name}({a:#x}, {b:#x})");
                }
            }
        }
    }
}
