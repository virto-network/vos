//! `Scalar` newtype + low-level scalar ABI fns.
//!
//! Wraps `curve25519_dalek::scalar::Scalar` so we can override `Mul`
//! and `Add` to dispatch through `ECALL_SCALAR_MUL_MOD_L` /
//! `_ADD_MOD_L` on the riscv64 target.  Off-target the operators
//! fall through to dalek directly.

use core::ops::Mul;
use curve25519_dalek::scalar::Scalar as DalekScalar;

#[cfg(target_arch = "riscv64")]
use crate::ecalls::{
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
    VOS_OBJECT_CAP,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub DalekScalar);

impl Scalar {
    pub fn from_canonical_bytes(b: [u8; 32]) -> Option<Self> {
        DalekScalar::from_canonical_bytes(b).into_option().map(Self)
    }

    /// Construct a Scalar from bytes that the caller PROMISES are
    /// canonical (< ℓ), bypassing dalek's montgomery_reduce-based
    /// validation.  Step 15 found that the validation chain trips
    /// a per-row constraint failure in some pre-existing chip; this
    /// helper avoids that path while preserving the canonicality
    /// guarantee on the result.
    ///
    /// SAFETY contract: the input bytes MUST encode a value < ℓ.
    /// Used by the shim's `from_bytes_mod_order_wide` (output is
    /// canonical by construction) and by cipher-clerk's
    /// `Blinding::to_dalek` (Blinding's own canonicality contract).
    pub fn from_canonical_bytes_unchecked(b: [u8; 32]) -> Self {
        // SAFETY: DalekScalar is a transparent newtype around
        // [u8; 32] with an invariant that the value is < ℓ.  The
        // caller guarantees that invariant.  transmute is layout-
        // equivalent (`#[repr(C)]` not required for newtype-of-array
        // single-field structs in stable layout).
        let s: DalekScalar = unsafe { core::mem::transmute(b) };
        Self(s)
    }

    pub fn from_bytes_mod_order_wide(b: &[u8; 64]) -> Self {
        // On PVM, dispatch to the ECALL precompile so the wide-scalar
        // reduction doesn't inflate the trace by ~60%.  Off PVM, fall
        // back to dalek's u64 backend (the host fallback inside
        // `scalar_from_bytes_mod_order_wide` does the same thing).
        let canonical = scalar_from_bytes_mod_order_wide(b);
        // SAFETY: `canonical` is < ℓ (precompile guarantees),
        // satisfying Scalar's canonicality invariant.
        let dalek_scalar: DalekScalar = unsafe { core::mem::transmute(canonical) };
        Self(dalek_scalar)
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
    fn from(v: u64) -> Self {
        Self(DalekScalar::from(v))
    }
}
impl From<u32> for Scalar {
    fn from(v: u32) -> Self {
        Self(DalekScalar::from(v))
    }
}
impl From<DalekScalar> for Scalar {
    fn from(s: DalekScalar) -> Self {
        Self(s)
    }
}

// On PVM, dispatches to ECALL_SCALAR_MUL_MOD_L / _ADD_MOD_L so the
// guest doesn't run dalek's u64 montgomery_mul/add chain inside the
// trace.  Off PVM, falls through to dalek directly.

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, rhs: &'b Scalar) -> Scalar {
        let bytes = scalar_mul_mod_l(&self.0.to_bytes(), &rhs.0.to_bytes());
        Scalar::from_canonical_bytes_unchecked(bytes)
    }
}
impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Scalar {
        (&self).mul(&rhs)
    }
}

impl<'a, 'b> core::ops::Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn add(self, rhs: &'b Scalar) -> Scalar {
        let bytes = scalar_add_mod_l(&self.0.to_bytes(), &rhs.0.to_bytes());
        Scalar::from_canonical_bytes_unchecked(bytes)
    }
}
impl core::ops::Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Scalar {
        (&self).add(&rhs)
    }
}

// ── Low-level ABI fns (kept public for prover-side trace integration) ──

/// `(a * b) mod ℓ` — mirrors dalek's `Scalar * Scalar`.  Inputs are
/// canonical 32-byte little-endian scalars.  Output is canonical.
pub fn scalar_mul_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_mul_mod_l_pvm(a, b)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_mul_mod_l_host(a, b)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_mul_mod_l_pvm(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let a_ptr = a.as_ptr() as u64;
    let b_ptr = b.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_MUL_MOD_L as u64,
            in("a0") a_ptr,
            in("a1") b_ptr,
            in("a2") output_ptr,
            in("a3") 0u64, in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_mul_mod_l_host(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let sa = DalekScalar::from_canonical_bytes(*a).into_option();
    let sb = DalekScalar::from_canonical_bytes(*b).into_option();
    match (sa, sb) {
        (Some(x), Some(y)) => (x * y).to_bytes(),
        _ => [0u8; 32],
    }
}

/// `(a + b) mod ℓ` — mirrors dalek's `Scalar + Scalar`.
pub fn scalar_add_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_add_mod_l_pvm(a, b)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_add_mod_l_host(a, b)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_add_mod_l_pvm(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let a_ptr = a.as_ptr() as u64;
    let b_ptr = b.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_ADD_MOD_L as u64,
            in("a0") a_ptr,
            in("a1") b_ptr,
            in("a2") output_ptr,
            in("a3") 0u64, in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_add_mod_l_host(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let sa = DalekScalar::from_canonical_bytes(*a).into_option();
    let sb = DalekScalar::from_canonical_bytes(*b).into_option();
    match (sa, sb) {
        (Some(x), Some(y)) => (x + y).to_bytes(),
        _ => [0u8; 32],
    }
}

/// Reduce 64 uniform-random bytes to a canonical scalar mod ℓ.
/// Returns the canonical 32-byte little-endian encoding.  On a
/// host build this delegates to `curve25519-dalek`'s
/// `Scalar::from_bytes_mod_order_wide`; on a PVM build it issues
/// `ecall ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub fn scalar_from_bytes_mod_order_wide(wide: &[u8; 64]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        scalar_from_bytes_mod_order_wide_pvm(wide)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        scalar_from_bytes_mod_order_wide_host(wide)
    }
}

#[cfg(target_arch = "riscv64")]
fn scalar_from_bytes_mod_order_wide_pvm(wide: &[u8; 64]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let wide_ptr = wide.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64,
            in("a0") wide_ptr,
            in("a1") output_ptr,
            in("a2") 0u64,
            in("a3") 0u64,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
    output
}

#[cfg(not(target_arch = "riscv64"))]
fn scalar_from_bytes_mod_order_wide_host(wide: &[u8; 64]) -> [u8; 32] {
    DalekScalar::from_bytes_mod_order_wide(wide).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_mul_matches_dalek() {
        let a = DalekScalar::from(7u64);
        let b = DalekScalar::from(13u64);
        let ours = scalar_mul_mod_l(&a.to_bytes(), &b.to_bytes());
        let theirs = (a * b).to_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn scalar_add_matches_dalek() {
        let a = DalekScalar::from(123u64);
        let b = DalekScalar::from(456u64);
        let ours = scalar_add_mod_l(&a.to_bytes(), &b.to_bytes());
        let theirs = (a + b).to_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn typed_scalar_arithmetic_matches_dalek() {
        // k + e * sk, the Schnorr signing operation.
        let k = Scalar::from(99u64);
        let e = Scalar::from(7u64);
        let sk = Scalar::from(13u64);
        let s_typed = &k + &(&e * &sk);
        let s_dalek = DalekScalar::from(99u64) + DalekScalar::from(7u64) * DalekScalar::from(13u64);
        assert_eq!(s_typed.0, s_dalek);
    }
}
