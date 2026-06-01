//! Hostcall ID constants — wire ABI between guest precompile shims
//! and the prover's `RistrettoChip` / `Blake2bChip` / `RistrettoEcallChip`.
//!
//! Always-on (no feature gate): these are tiny integer constants and
//! both the `ristretto` and `blake2b` modules reference them.  Mirrors
//! the corresponding constants in `zkpvm::core::ecall`.
//!
//! **Slot range**: javm's `dispatch_ecalli` rejects `imm > 127` with a
//! fault, so every precompile ID fits in `0..=127` — packed into the
//! contiguous `100..=115` block within javm's program-cap range
//! (slots 64..=127). The original categorisation by hundreds
//! (1xx hash, 2xx asymmetric crypto) didn't survive the imm budget.

/// Ristretto255 scalar-mult precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_SCALAR_MULT`.
pub const ECALL_RISTRETTO_SCALAR_MULT: u32 = 110;

/// Ristretto255 compressed-point addition precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_RISTRETTO_POINT_ADD`.
pub const ECALL_RISTRETTO_POINT_ADD: u32 = 111;

/// Wide-scalar reduction precompile.
/// Mirrors `zkpvm::core::ecall::ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE`.
pub const ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE: u32 = 112;

/// `Scalar * Scalar mod ℓ`.
pub const ECALL_SCALAR_MUL_MOD_L: u32 = 113;

/// `Scalar + Scalar mod ℓ`.
pub const ECALL_SCALAR_ADD_MOD_L: u32 = 114;

/// One blake2b compression per call.
/// Mirrors `zkpvm::core::ecall::ECALL_BLAKE2B_COMPRESS`.
/// Convention: φ[10]=h_ptr (64B in/out), φ[11]=m_ptr (128B in),
/// φ[12]=t_low (counter low 64 bits), φ[7]=f (finalize flag).
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;

/// ZK actor-IO binding (Phase ZK-ABI).
/// Mirrors `zkpvm::core::ecall::ECALL_ZK_BIND`.  The guest shim for this
/// ID lives in the `vos` crate (`vos::zk::ecall_zk_bind`), not here, but
/// the constant is mirrored to keep the wire-ABI table complete and
/// prevent a future precompile from re-using slot 115.
/// Convention: φ[7]=ptr (32-byte hash in flat_mem), φ[8]=len (≥ 32);
/// the tracer writes the hash into φ[9..13].
pub const ECALL_ZK_BIND: u32 = 115;

/// VOS object capability slot used by the inline-asm ECALL dispatch.
/// Set into `a5` on every call.  Only referenced from
/// `cfg(target_arch = "riscv64")` blocks — on host builds it's
/// unreachable but kept defined for symmetry.
#[cfg(target_arch = "riscv64")]
pub(crate) const VOS_OBJECT_CAP: u64 = 65;
