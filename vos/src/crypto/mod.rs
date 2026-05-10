//! Crypto precompiles — single-entry-point hashes/curves available to
//! every actor and worker.
//!
//! The shape mirrors `zkpvm-precompiles`: each algorithm exposes a
//! high-level helper that on `target_arch = "riscv64"` dispatches to
//! a host ECALL (so PVM actors get the host's accelerated impl), and
//! on every other target falls through to a self-contained software
//! reference. Same code path runs in tests, workers, and PVM — the
//! cfg gate just picks the backend.
//!
//! Today this is just blake2b. Future precompiles (ed25519, sha2,
//! ristretto) slot in as sibling submodules.

pub mod blake2b;

pub use blake2b::{ECALL_BLAKE2B_COMPRESS, blake2b_hash};
