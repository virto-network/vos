//! `RistrettoPoint` newtype + low-level point ABI fns.
//!
//! Holds 32 compressed bytes inline so operator overloads (`Mul`,
//! `Add`) can issue PVM ECALLs directly without first compressing the
//! operands.  Eliminates the decompress + recompress round-trips that
//! previously bloated the PVM trace by ~10× per operation.
//!
//! Conversion to/from dalek's `RistrettoPoint` (the decompressed
//! extended-coords form) goes through `from_dalek` / `into_dalek` —
//! these run dalek-internal field arithmetic on the host and expand
//! the PVM trace, so use sparingly.

use core::ops::Mul;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint as DalekRistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;

#[cfg(target_arch = "riscv64")]
use crate::ecalls::{ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT, VOS_OBJECT_CAP};
use crate::scalar::Scalar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoPoint(pub [u8; 32]);

impl RistrettoPoint {
    /// The 32-byte compressed encoding (this is the wire form).
    pub fn compress(&self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&self.0).expect("RistrettoPoint always holds 32 bytes")
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn from_uniform_bytes(b: &[u8; 64]) -> Self {
        Self(
            DalekRistrettoPoint::from_uniform_bytes(b)
                .compress()
                .to_bytes(),
        )
    }
    /// Canonical compressed identity.
    pub fn identity() -> Self {
        Self([0u8; 32])
    }
    /// Wrap a dalek decompressed point — runs `compress()` host-side.
    /// Heavy: prefer to keep operands in compressed form throughout
    /// any chain of operations; only convert at the boundary.
    pub fn from_dalek(p: DalekRistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }
    /// Decompress to dalek — runs `decompress()` host-side.  Heavy.
    pub fn into_dalek(self) -> DalekRistrettoPoint {
        CompressedRistretto::from_slice(&self.0)
            .ok()
            .and_then(|c| c.decompress())
            .unwrap_or_default()
    }
}

impl From<DalekRistrettoPoint> for RistrettoPoint {
    fn from(p: DalekRistrettoPoint) -> Self {
        Self::from_dalek(p)
    }
}

impl core::ops::Add for RistrettoPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        (&self).add(&rhs)
    }
}
impl<'a, 'b> core::ops::Add<&'b RistrettoPoint> for &'a RistrettoPoint {
    type Output = RistrettoPoint;
    fn add(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(ristretto_point_add(&self.0, &rhs.0))
    }
}

/// Fixed-base scalar mult against the Ristretto255 basepoint.
/// `&scalar * &RISTRETTO_BASEPOINT_TABLE` mirrors dalek's API.
pub struct RistrettoBasepointTable;

/// Singleton instance to mirror dalek's `RISTRETTO_BASEPOINT_TABLE`
/// constant.  Indirection through this type lets the `Mul` impl
/// dispatch to the ECALL on PVM.
pub const RISTRETTO_BASEPOINT_TABLE: RistrettoBasepointTable = RistrettoBasepointTable;

// ── Multiplications ──────────────────────────────────────────────

impl<'a, 'b> Mul<&'b RistrettoBasepointTable> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, _: &'b RistrettoBasepointTable) -> RistrettoPoint {
        scalar_mult_dispatch(self, &basepoint_compressed_bytes())
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        scalar_mult_dispatch(self, &rhs.0)
    }
}

// Allow `scalar * &point` (by-value scalar) too, for ergonomics.
impl<'b> Mul<&'b RistrettoPoint> for Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        (&self).mul(rhs)
    }
}
impl<'a> Mul<RistrettoPoint> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: RistrettoPoint) -> RistrettoPoint {
        self.mul(&rhs)
    }
}

fn scalar_mult_dispatch(scalar: &Scalar, point: &[u8; 32]) -> RistrettoPoint {
    let scalar_bytes = scalar.to_bytes();
    let out = ristretto_scalar_mult(&scalar_bytes, point);
    RistrettoPoint(out)
}

fn basepoint_compressed_bytes() -> [u8; 32] {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()
}

// ── Low-level ABI fns (kept public for prover-side trace integration) ──

/// Compute `k · P → Q` for a Ristretto255 scalar `k` and compressed
/// point `P`.  Returns the compressed encoding of `Q`.
///
/// Returns `[0u8; 32]` (canonical compressed identity) on either
/// non-canonical scalar bytes or invalid input point encoding.
pub fn ristretto_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        ristretto_scalar_mult_pvm(scalar, point)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        ristretto_scalar_mult_host(scalar, point)
    }
}

#[cfg(target_arch = "riscv64")]
fn ristretto_scalar_mult_pvm(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let scalar_ptr = scalar.as_ptr() as u64;
    let point_ptr = point.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_RISTRETTO_SCALAR_MULT as u64,
            in("a0") scalar_ptr,
            in("a1") point_ptr,
            in("a2") output_ptr,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn ristretto_scalar_mult_host(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let s = match DalekScalar::from_canonical_bytes(*scalar).into_option() {
        Some(s) => s,
        None => return [0u8; 32],
    };
    let p = match CompressedRistretto::from_slice(point)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    (s * p).compress().to_bytes()
}

/// Compute `P + Q` for two compressed Ristretto255 points.  Returns
/// the compressed encoding of the sum.  Returns `[0u8; 32]`
/// (canonical compressed identity) on either invalid input encoding.
pub fn ristretto_point_add(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        ristretto_point_add_pvm(p, q)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        ristretto_point_add_host(p, q)
    }
}

#[cfg(target_arch = "riscv64")]
fn ristretto_point_add_pvm(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let p_ptr = p.as_ptr() as u64;
    let q_ptr = q.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_RISTRETTO_POINT_ADD as u64,
            in("a0") p_ptr,
            in("a1") q_ptr,
            in("a2") output_ptr,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn ristretto_point_add_host(p: &[u8; 32], q: &[u8; 32]) -> [u8; 32] {
    let pp = match CompressedRistretto::from_slice(p)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    let qq = match CompressedRistretto::from_slice(q)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(q) => q,
        None => return [0u8; 32],
    };
    (pp + qq).compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn typed_scalar_mult_basepoint_matches_dalek() {
        let v: Scalar = 50u64.into();
        let g = &RISTRETTO_BASEPOINT_TABLE;
        let ours = &v * g;
        let theirs = (DalekScalar::from(50u64) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn typed_scalar_mult_arbitrary_point_matches_dalek() {
        let v: Scalar = 7u64.into();
        let p_dalek = DalekScalar::from(3u64) * RISTRETTO_BASEPOINT_POINT;
        let p = RistrettoPoint::from_dalek(p_dalek);
        let ours = &v * &p;
        let theirs = (DalekScalar::from(7u64) * p_dalek).compress().to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn pedersen_style_vg_plus_bh_matches_dalek() {
        let v: Scalar = 100u64.into();
        let b = Scalar::from_bytes_mod_order_wide(&[0x37; 64]);
        // Synthesize an H point off the basepoint for the test.
        let h_dalek = DalekScalar::from(7u64) * RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::from_dalek(h_dalek);
        let g = &RISTRETTO_BASEPOINT_TABLE;
        let p = &v * g + &b * &h;
        let theirs = (DalekScalar::from(100u64) * RISTRETTO_BASEPOINT_POINT + b.0 * h_dalek)
            .compress()
            .to_bytes();
        assert_eq!(p.0, theirs);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn point_add_matches_dalek() {
        let p_dalek = DalekScalar::from(7u64) * RISTRETTO_BASEPOINT_POINT;
        let q_dalek = DalekScalar::from(13u64) * RISTRETTO_BASEPOINT_POINT;
        let p = RistrettoPoint::from_dalek(p_dalek);
        let q = RistrettoPoint::from_dalek(q_dalek);
        let ours = &p + &q;
        let theirs = (p_dalek + q_dalek).compress().to_bytes();
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn raw_byte_api_2_times_g_matches_dalek() {
        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        let ours = ristretto_scalar_mult(&scalar, &point);
        let theirs = (DalekScalar::from(2u64) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        assert_eq!(ours, theirs);
    }
}
