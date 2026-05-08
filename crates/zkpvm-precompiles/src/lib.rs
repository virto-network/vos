//! Guest-side shims for zkpvm precompile ECALLs.
//!
//! The shim re-exports `Scalar`, `RistrettoPoint`, and basepoint
//! constants from `curve25519-dalek` (under the `ristretto` feature)
//! plus a streaming `blake2b_hash` (under the `blake2b` feature) so
//! consumer code reads identically to plain dalek/blake2:
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
//! `Mul` / `Add` impls dispatch to inline-asm `ecall` that the
//! prover's chips intercept and accelerate.  On non-riscv64 targets
//! they fall through to dalek's / a bundled software reference.
//!
//! ## Features
//!
//! - `ristretto` (default) — `Scalar`, `RistrettoPoint`,
//!   `RISTRETTO_BASEPOINT_TABLE`, plus the low-level
//!   `ristretto_scalar_mult`, `ristretto_point_add`,
//!   `scalar_mul_mod_l`, `scalar_add_mod_l`,
//!   `scalar_from_bytes_mod_order_wide` ABI fns.  Pulls in
//!   `curve25519-dalek`.
//! - `blake2b` (default) — `blake2b_compress` (one compression per
//!   call) plus the streaming `blake2b_hash::<N>(domain, parts)`
//!   high-level helper.  Self-contained — no extra runtime deps.
//!
//! Default = `["ristretto", "blake2b"]`.  Guests that only need
//! hashing can opt out of dalek with `default-features = false,
//! features = ["blake2b"]`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod ecalls;
pub use ecalls::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
};

#[cfg(feature = "blake2b")]
pub mod blake2b;
#[cfg(feature = "blake2b")]
pub use blake2b::{blake2b_compress, blake2b_hash};

#[cfg(feature = "ristretto")]
pub mod scalar;
#[cfg(feature = "ristretto")]
pub use scalar::{
    scalar_add_mod_l, scalar_from_bytes_mod_order_wide, scalar_mul_mod_l, Scalar,
};

#[cfg(feature = "ristretto")]
pub mod ristretto;
#[cfg(feature = "ristretto")]
pub use ristretto::{
    ristretto_point_add, ristretto_scalar_mult, RistrettoBasepointTable, RistrettoPoint,
    RISTRETTO_BASEPOINT_TABLE,
};
