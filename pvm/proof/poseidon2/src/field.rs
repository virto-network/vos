//! The Mersenne-31 field, `p = 2^31 - 1`.

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub};

/// The modulus `2^31 - 1`.
pub const P: u32 = (1 << 31) - 1;

/// An element of the field, held canonical, in `[0, p)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct M31(u32);

impl M31 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    /// The element `value`, which must be canonical.
    ///
    /// # Panics
    /// When `value ≥ p`.
    pub const fn new(value: u32) -> Self {
        assert!(value < P, "an M31 word is below p");
        Self(value)
    }

    /// `value mod p`, for `value < 2p²`.
    pub const fn reduce(value: u64) -> Self {
        let quotient = ((value >> 31) + value + 1) >> 31;
        Self(((quotient + value) & P as u64) as u32)
    }

    /// `value mod p`, for `value < 2p`.
    fn partial_reduce(value: u32) -> Self {
        Self(value.checked_sub(P).unwrap_or(value))
    }

    /// The canonical value, in `[0, p)`.
    pub const fn value(self) -> u32 {
        self.0
    }

    /// `self^5`, the S-box.
    pub fn pow5(self) -> Self {
        let square = self * self;
        square * square * self
    }
}

impl From<u32> for M31 {
    /// `value mod p`.
    fn from(value: u32) -> Self {
        // `2^31 ≡ 1`, so the top bit folds onto the rest, below p + 2.
        Self::partial_reduce((value & P) + (value >> 31))
    }
}

impl Add for M31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        // Both below 2^31, so the sum fits and lies below 2p.
        Self::partial_reduce(self.0 + rhs.0)
    }
}

impl AddAssign for M31 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for M31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::partial_reduce(self.0 + P - rhs.0)
    }
}

impl Mul for M31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::reduce(u64::from(self.0) * u64::from(rhs.0))
    }
}

impl MulAssign for M31 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operations_agree_with_integer_arithmetic_mod_p() {
        let p = u64::from(P);
        let samples = [0, 1, 2, 3, 0xffff, 0x1_0000, P / 2, P - 2, P - 1];
        for a in samples {
            for b in samples {
                let (x, y) = (M31::new(a), M31::new(b));
                let (a, b) = (u64::from(a), u64::from(b));
                assert_eq!(u64::from((x + y).value()), (a + b) % p);
                assert_eq!(u64::from((x - y).value()), (a + p - b) % p);
                assert_eq!(u64::from((x * y).value()), a * b % p);
            }
        }
        for value in [
            0,
            1,
            p - 1,
            p,
            p + 1,
            2 * p,
            u64::from(u32::MAX),
            (p - 1) * (p - 1),
        ] {
            assert_eq!(u64::from(M31::reduce(value).value()), value % p);
        }
        for value in [0, 1, P - 1, P, P + 1, 2 * P, u32::MAX] {
            assert_eq!(M31::from(value).value(), value % P);
        }
    }
}
