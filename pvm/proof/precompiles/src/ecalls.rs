//! Host-call identifiers — the wire ABI between guest precompile shims
//! and the prover's `RistrettoChip` / `Blake2bChip` / `RistrettoEcallChip`.
//!
//! Always-on (no feature gate): these are tiny integer constants and
//! both the `ristretto` and `blake2b` modules reference them.  Mirrors
//! the corresponding constants in `vos_pvm_proof::core::ecall`.

/// Ristretto255 scalar-mult precompile.
/// Mirrors `vos_pvm_proof::core::ecall::ECALL_RISTRETTO_SCALAR_MULT`.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 110;

/// Ristretto255 compressed-point addition precompile.
/// Mirrors `vos_pvm_proof::core::ecall::ECALL_RISTRETTO_POINT_ADD`.
pub const ECALL_RISTRETTO_POINT_ADD: u32 = 111;

/// Wide-scalar reduction precompile.
/// Mirrors `vos_pvm_proof::core::ecall::ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub const ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE: u32 = 112;

/// `Scalar * Scalar mod ℓ`.
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 113;

/// `Scalar + Scalar mod ℓ`.
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 114;

/// One blake2b compression per call.
/// Mirrors `vos_pvm_proof::core::ecall::ECALL_BLAKE2B_COMPRESS`.
/// Convention: φ[7]=h_ptr (64B in/out), φ[8]=m_ptr (128B in),
/// φ[9]=t_low (counter low 64 bits), φ[10]=f (finalize flag).
pub const ECALL_BLAKE2B_COMPRESS: u32 = 0x400;
