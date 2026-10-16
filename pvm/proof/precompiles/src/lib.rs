//! Guest-side shims for vos-pvm-proof precompile ECALLs.
//!
//! The shim re-exports `Scalar`, `RistrettoPoint`, and basepoint
//! constants from `curve25519-dalek` (under the `ristretto` feature)
//! plus a streaming `blake2b_hash` (under the `blake2b` feature) so
//! consumer code reads identically to plain dalek/blake2:
//!
//! ```
//! use vos_pvm_precompiles::{RISTRETTO_BASEPOINT_TABLE, RistrettoPoint, Scalar};
//! let v = Scalar::from(7u64);
//! let b = Scalar::from(3u64);
//! let g = &RISTRETTO_BASEPOINT_TABLE;
//! let h: RistrettoPoint = &Scalar::from(5u64) * g;
//! let p = &v * g + b * &h;
//! assert_eq!(p, &Scalar::from(22u64) * g);
//! ```
//!
//! On `target_arch = "riscv64"` (the guest target), the `Mul` / `Add`
//! impls make precompile host calls, which the prover's chips record, and
//! compute in software when the host answers `WHAT`. On other targets they
//! run dalek or a bundled software reference.
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
//!   high-level helper, and a kernel's io-hash (`compute_io_hash`).
//!   Self-contained — no extra runtime deps.
//!
//! Default = `["ristretto", "blake2b"]`.  Guests that only need
//! hashing can opt out of dalek with `default-features = false,
//! features = ["blake2b"]`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
// Cryptographic code paths use index-based loops to mirror reference
// implementations (RFC 7693 round constants, dalek's named lifetimes
// across multiple impls). Allowed crate-wide so the workspace's
// `-D warnings` gate doesn't reject this verbatim port.
#![allow(clippy::needless_range_loop, clippy::needless_lifetimes)]

#[cfg(test)]
extern crate alloc;

pub mod ecalls;
pub use ecalls::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
};

#[cfg(feature = "blake2b")]
pub mod blake2b;
#[cfg(feature = "blake2b")]
pub use blake2b::{Blake2b256, blake2b_256, blake2b_compress, blake2b_hash};

#[cfg(feature = "blake2b")]
pub mod io;
#[cfg(feature = "blake2b")]
pub use io::{RootRead, compute_io_hash};

#[cfg(feature = "ristretto")]
pub mod scalar;
#[cfg(feature = "ristretto")]
pub use scalar::{Scalar, scalar_add_mod_l, scalar_from_bytes_mod_order_wide, scalar_mul_mod_l};

#[cfg(feature = "ristretto")]
pub mod ristretto;
#[cfg(feature = "ristretto")]
pub use ristretto::{
    RISTRETTO_BASEPOINT_TABLE, RistrettoBasepointTable, RistrettoPoint, ristretto_point_add,
    ristretto_scalar_mult,
};
