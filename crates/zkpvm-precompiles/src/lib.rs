//! Guest-side shims for zkpvm precompile ECALLs.
//!
//! The shim re-exports `Scalar`, `RistrettoPoint`, and basepoint
//! constants from `curve25519-dalek` so consumer code reads
//! identically to plain dalek:
//!
//! ```ignore
//! use zkpvm_precompiles::{Scalar, RistrettoPoint, RISTRETTO_BASEPOINT_TABLE};
//! let v: Scalar = ...;
//! let g = &RISTRETTO_BASEPOINT_TABLE;
//! let h: RistrettoPoint = ...;
//! let p = &v * g + b * &h;
//! ```
//!
//! On `target_arch = "riscv64"` (the zkpvm guest target), the
//! `Mul` impls dispatch to an inline-asm `ecalli 200` that the
//! prover's `RistrettoChip` intercepts and accelerates via the
//! chip's witness/constraints.  On non-riscv64 targets the
//! multiplications fall through to dalek's native `Mul`.
//!
//! The wire ABI for the ECALL:
//!
//!   - hostcall ID 200 (`ECALL_RISTRETTO_SCALAR_MULT`)
//!   - φ[10] = scalar_ptr (32 canonical bytes, scalar mod ℓ)
//!   - φ[11] = point_ptr  (32 bytes, compressed Ristretto)
//!   - φ[12] = output_ptr (32 bytes, written by the call)
//!
//! Returns `[0u8; 32]` (canonical compressed identity) on either
//! non-canonical scalar or invalid input point.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::ops::Mul;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint as DalekRistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;

/// Hostcall ID for the Ristretto255 scalar-mult precompile.  Mirrors
/// `zkpvm::core::ecall::ECALL_RISTRETTO_SCALAR_MULT` in the prover.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;

/// Re-exports of dalek's types, so consumers don't depend on dalek
/// directly.  Wrapping is unnecessary since we override `Mul` for
/// references to these types; dalek's own `Mul` impls live next to
/// them but are shadowed by ours when `&Scalar * &RistrettoPoint`
/// or `&Scalar * &Basepoint` is invoked through this crate's
/// re-export chain.  However Rust's coherence rules don't let us
/// override foreign `Mul` impls on foreign types, so we wrap.
///
/// `Scalar` and `RistrettoPoint` are thin newtypes: `Deref` to
/// dalek's types so all dalek methods (compress, from_uniform_bytes,
/// from_canonical_bytes, etc.) are available transparently.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub DalekScalar);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoPoint(pub DalekRistrettoPoint);

impl Scalar {
    pub fn from_canonical_bytes(b: [u8; 32]) -> Option<Self> {
        DalekScalar::from_canonical_bytes(b).into_option().map(Self)
    }
    pub fn from_bytes_mod_order_wide(b: &[u8; 64]) -> Self {
        Self(DalekScalar::from_bytes_mod_order_wide(b))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
    pub const ZERO: Self = Self(DalekScalar::ZERO);
    pub const ONE: Self = Self(DalekScalar::ONE);
}

impl From<u64> for Scalar {
    fn from(v: u64) -> Self { Self(DalekScalar::from(v)) }
}
impl From<u32> for Scalar {
    fn from(v: u32) -> Self { Self(DalekScalar::from(v)) }
}
impl From<DalekScalar> for Scalar {
    fn from(s: DalekScalar) -> Self { Self(s) }
}

impl RistrettoPoint {
    pub fn compress(&self) -> CompressedRistretto {
        self.0.compress()
    }
    pub fn from_uniform_bytes(b: &[u8; 64]) -> Self {
        Self(DalekRistrettoPoint::from_uniform_bytes(b))
    }
    pub fn identity() -> Self {
        Self(DalekRistrettoPoint::default())
    }
    pub fn from_dalek(p: DalekRistrettoPoint) -> Self { Self(p) }
    pub fn into_dalek(self) -> DalekRistrettoPoint { self.0 }
}

impl From<DalekRistrettoPoint> for RistrettoPoint {
    fn from(p: DalekRistrettoPoint) -> Self { Self(p) }
}

impl core::ops::Add for RistrettoPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self(self.0 + rhs.0) }
}
impl<'a, 'b> core::ops::Add<&'b RistrettoPoint> for &'a RistrettoPoint {
    type Output = RistrettoPoint;
    fn add(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(self.0 + rhs.0)
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
        // k * G — fixed-base.  ECALL with point = compressed
        // basepoint bytes.
        scalar_mult_dispatch(self, &basepoint_compressed_bytes())
    }
}

impl<'a, 'b> Mul<&'b RistrettoPoint> for &'a Scalar {
    type Output = RistrettoPoint;
    fn mul(self, rhs: &'b RistrettoPoint) -> RistrettoPoint {
        let pb = rhs.0.compress().to_bytes();
        scalar_mult_dispatch(self, &pb)
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
    // Decompress the chip's output back to a RistrettoPoint.  The
    // chip returns the canonical compressed encoding; if it's all
    // zeros (chip's malformed-input branch), this is identity.
    let compressed = CompressedRistretto::from_slice(&out)
        .expect("chip output is always 32 bytes")
        .decompress()
        .unwrap_or(DalekRistrettoPoint::default());
    RistrettoPoint(compressed)
}

fn basepoint_compressed_bytes() -> [u8; 32] {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()
}

// ── Low-level ABI (kept public for Step 3 trace integration) ──

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
    const VOS_OBJECT_CAP: u64 = 65;
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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn typed_scalar_mult_basepoint_matches_dalek() {
        let v: Scalar = 50u64.into();
        let g = &RISTRETTO_BASEPOINT_TABLE;
        let ours = &v * g;
        let theirs = DalekScalar::from(50u64) * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(ours.0, theirs);
    }

    #[test]
    fn typed_scalar_mult_arbitrary_point_matches_dalek() {
        let v: Scalar = 7u64.into();
        let p_dalek = DalekScalar::from(3u64) * RISTRETTO_BASEPOINT_POINT;
        let p = RistrettoPoint::from_dalek(p_dalek);
        let ours = &v * &p;
        let theirs = DalekScalar::from(7u64) * p_dalek;
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
        let theirs = DalekScalar::from(100u64) * RISTRETTO_BASEPOINT_POINT
            + b.0 * h_dalek;
        assert_eq!(p.0, theirs);
    }

    #[test]
    fn raw_byte_api_2_times_g_matches_dalek() {
        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        let ours = ristretto_scalar_mult(&scalar, &point);
        let theirs = (DalekScalar::from(2u64) * RISTRETTO_BASEPOINT_POINT)
            .compress().to_bytes();
        assert_eq!(ours, theirs);
    }
}
