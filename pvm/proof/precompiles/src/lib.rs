//! Guest-side shims for vos-pvm-proof precompile ECALLs.
//!
//! The shim provides a streaming `blake2b_hash` (under the `blake2b`
//! feature), a kernel's io-hash and the Poseidon2-M31 compression
//! (`poseidon2_compress`). On `target_arch = "riscv64"` (the guest target)
//! each compression makes a precompile host call, which the prover's chips
//! record, and computes in software when the host answers `WHAT`. On other
//! targets it runs a software reference: the BLAKE2b one bundled here, the
//! Poseidon2 permutation of `vos-pvm-poseidon2`.
//!
//! ## Features
//!
//! - `blake2b` (default) — `blake2b_compress` (one compression per
//!   call) plus the streaming `blake2b_hash::<N>(domain, parts)`
//!   high-level helper, and a kernel's io-hash (`compute_io_hash`).
//!   Self-contained — no extra runtime deps.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
// Cryptographic code paths use index-based loops to mirror reference
// implementations (RFC 7693 round constants). Allowed crate-wide so the
// workspace's `-D warnings` gate doesn't reject this verbatim port.
#![allow(clippy::needless_range_loop)]

#[cfg(test)]
extern crate alloc;

pub mod ecalls;
pub use ecalls::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2};

pub mod blake2b;
pub use blake2b::{
    BLAKE2B_IV, Blake2b256, blake2b_256, blake2b_compress, blake2b_compress_words, blake2b_hash,
};

pub mod io;
pub use io::{RootKind, RootRead, UnknownRootKind, compute_io_hash};

pub mod poseidon2;
pub use poseidon2::{
    checked_poseidon2_compress_block, poseidon2_compress, poseidon2_compress_block,
    poseidon2_compress_into,
};
