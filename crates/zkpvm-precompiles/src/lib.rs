//! Guest-side shims for zkpvm precompile ECALLs.
//!
//! Each precompile is a hostcall slot the zkpvm prover intercepts and
//! replaces with chip-accelerated row-emission.  The on-target path is
//! `core::arch::asm` with the JAM ABI:
//!
//!   - `t0`           = hostcall ID (slot number)
//!   - `a0..=a5`      = up to 6 u64 arguments (RISC-V x10..=x15;
//!                       grey-transpiler maps to PVM φ[7..=12])
//!   - `inlateout(a0)`= 1 u64 return value
//!
//! This crate is `no_std` by default and pulls in nothing on the
//! on-target build (the on-target shims are pure inline asm).  The
//! `host-fallback` feature enables a dalek-backed host implementation
//! so the same call sites compile and run in tests / development on
//! non-riscv64 targets.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "host-fallback")]
extern crate alloc;

/// Hostcall ID for the Ristretto255 scalar-mult precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_SCALAR_MULT` in
/// the prover crate (kept in sync at the integration boundary
/// — this constant is the wire-format anchor).
///
/// Convention:
///   φ[10] = scalar_ptr (32 canonical bytes, scalar mod ℓ)
///   φ[11] = point_ptr  (32 bytes, compressed Ristretto)
///   φ[12] = output_ptr (32 bytes, written by the call)
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;

/// Compute `k · P → Q` for a Ristretto255 scalar `k` and compressed
/// point `P`.  Returns the compressed encoding of `Q`.
///
/// Returns `[0u8; 32]` (canonical compressed identity) on either
/// non-canonical scalar bytes or invalid input point encoding —
/// matching the chip's malformed-input branch.
pub fn ristretto_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "riscv64")]
    {
        ristretto_scalar_mult_pvm(scalar, point)
    }
    #[cfg(all(not(target_arch = "riscv64"), feature = "host-fallback"))]
    {
        ristretto_scalar_mult_host(scalar, point)
    }
    #[cfg(all(not(target_arch = "riscv64"), not(feature = "host-fallback")))]
    {
        let _ = (scalar, point);
        panic!(
            "zkpvm-precompiles: off-target build needs `host-fallback` feature"
        );
    }
}

#[cfg(target_arch = "riscv64")]
fn ristretto_scalar_mult_pvm(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let scalar_ptr = scalar.as_ptr() as u64;
    let point_ptr = point.as_ptr() as u64;
    let output_ptr = output.as_mut_ptr() as u64;
    // VOS object cap (slot 65) — the stack DATA cap convention.  See
    // `vos::abi::pvm::ecall` for rationale.  Since our buffers all
    // live on the stack, this works; if a caller wants to pass
    // non-stack pointers they'd need a different ECALL.
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

#[cfg(all(not(target_arch = "riscv64"), feature = "host-fallback"))]
fn ristretto_scalar_mult_host(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;

    let s = match Scalar::from_canonical_bytes(*scalar).into_option() {
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
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;

    fn dalek_reference(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        let s = Scalar::from_canonical_bytes(*scalar)
            .into_option()
            .expect("canonical");
        let p = CompressedRistretto::from_slice(point)
            .ok()
            .and_then(|c| c.decompress())
            .expect("decompresses");
        (s * p).compress().to_bytes()
    }

    #[test]
    fn host_fallback_2_times_g_matches_dalek() {
        // Smoke test only runs in the host-fallback configuration.
        // (cfg gating below: only compile this body when the feature
        // is on, otherwise it's a no-op stub.)
        #[cfg(feature = "host-fallback")]
        {
            let mut scalar = [0u8; 32];
            scalar[0] = 2;
            let point = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
            let ours = ristretto_scalar_mult(&scalar, &point);
            let theirs = dalek_reference(&scalar, &point);
            assert_eq!(ours, theirs);
        }
        #[cfg(not(feature = "host-fallback"))]
        {
            let _ = (RISTRETTO_BASEPOINT_COMPRESSED, dalek_reference);
        }
    }

    #[test]
    fn host_fallback_random_scalar_matches_dalek() {
        #[cfg(feature = "host-fallback")]
        {
            let mut scalar = [0u8; 32];
            for i in 0..32 {
                scalar[i] = (i as u8).wrapping_mul(0x37);
            }
            scalar[31] &= 0x0f; // keep < ℓ for canonical
            let point = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
            let ours = ristretto_scalar_mult(&scalar, &point);
            let theirs = dalek_reference(&scalar, &point);
            assert_eq!(ours, theirs);
        }
    }

    #[test]
    fn host_fallback_non_canonical_scalar_returns_zero() {
        #[cfg(feature = "host-fallback")]
        {
            // ℓ exactly is non-canonical (must be < ℓ).  Using a
            // scalar with the top byte set to 0xFF guarantees > ℓ.
            let mut scalar = [0xffu8; 32];
            scalar[31] = 0xff;
            let point = RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
            let result = ristretto_scalar_mult(&scalar, &point);
            assert_eq!(result, [0u8; 32]);
        }
    }

    #[test]
    fn host_fallback_invalid_point_returns_zero() {
        #[cfg(feature = "host-fallback")]
        {
            let mut scalar = [0u8; 32];
            scalar[0] = 7;
            // 0xFF…FF is not a valid compressed Ristretto point.
            let point = [0xffu8; 32];
            let result = ristretto_scalar_mult(&scalar, &point);
            assert_eq!(result, [0u8; 32]);
        }
    }
}
