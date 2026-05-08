//! Hostcall ID constants — wire ABI between guest precompile shims
//! and the prover's `RistrettoChip` / `Blake2bChip` / `RistrettoEcallChip`.
//!
//! Always-on (no feature gate): these are tiny integer constants and
//! both the `ristretto` and `blake2b` modules reference them.  Mirrors
//! the corresponding constants in `zkpvm::core::ecall`.

/// Ristretto255 scalar-mult precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_SCALAR_MULT`.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 200;

/// Ristretto255 compressed-point addition precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_POINT_ADD`.
pub const ECALL_RISTRETTO_POINT_ADD: u32 = 201;

/// Wide-scalar reduction precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub const ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE: u32 = 202;

/// `Scalar * Scalar mod ℓ`.
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 203;

/// `Scalar + Scalar mod ℓ`.
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 204;

/// One blake2b compression per call.
/// Mirrors `zkpvm::core::ecall::ECALL_BLAKE2B_COMPRESS`.
/// Convention: φ[10]=h_ptr (64B in/out), φ[11]=m_ptr (128B in),
/// φ[12]=t_low (counter low 64 bits), φ[7]=f (finalize flag).
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;

/// VOS object capability slot used by the inline-asm ECALL dispatch.
/// Set into `a5` on every call.  Only referenced from
/// `cfg(target_arch = "riscv64")` blocks — on host builds it's
/// unreachable but kept defined for symmetry.
#[cfg(target_arch = "riscv64")]
pub(crate) const VOS_OBJECT_CAP: u64 = 65;
